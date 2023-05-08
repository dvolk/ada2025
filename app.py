import logging
import datetime
import enum
import threading
import time
import json
import string
import secrets
import subprocess

import argh
from flask import Flask, render_template, url_for, redirect, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import aliased
from sqlalchemy import Index
from flask_migrate import Migrate
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired

import humanize

import docker

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Association table for many-to-many relationship between User and Machine (shared_users)
shared_user_machine = db.Table(
    "shared_user_machine",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("machine_id", db.Integer, db.ForeignKey("machine.id")),
)
# Association table
user_data_source_association = db.Table(
    "user_data_source",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("data_source_id", db.Integer, db.ForeignKey("data_source.id")),
)


def gen_token(length):
    """
    Generate a cryptographically secure alphanumeric string of the given length.
    """
    alphabet = string.ascii_letters + string.digits
    secure_string = "".join(secrets.choice(alphabet) for _ in range(length))
    return secure_string


class User(db.Model, UserMixin):
    """
    User model, also used for flask-login
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    group = db.relationship("Group", back_populates="users")
    owned_machines = db.relationship(
        "Machine", back_populates="owner", foreign_keys="Machine.owner_id"
    )
    shared_machines = db.relationship(
        "Machine", secondary=shared_user_machine, back_populates="shared_users"
    )
    data_sources = db.relationship(
        "DataSource", secondary=user_data_source_association, back_populates="users"
    )
    data_transfer_jobs = db.relationship("DataTransferJob", back_populates="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class DataSource(db.Model):
    """
    The DataSource model represents a source of data for users that
    they can use to copy into their machine.

    This is done by SSHing into the source_host and then running
    rsync to sync the data into the machine ip.
    """

    id = db.Column(db.Integer, primary_key=True)
    source_host = db.Column(db.String, nullable=False)
    source_dir = db.Column(db.String, nullable=False)
    data_size = db.Column(db.Integer, nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    users = db.relationship(
        "User", secondary=user_data_source_association, back_populates="data_sources"
    )
    data_transfer_jobs = db.relationship(
        "DataTransferJob", back_populates="data_source"
    )


Index("source_host_source_dir_idx", DataSource.source_host, DataSource.source_dir)


class DataTransferJobState(enum.Enum):
    RUNNING = "R"
    DONE = "D"
    FAILED = "F"
    REMOVED = "R"


class DataTransferJob(db.Model):
    """
    The DataTransferJob tracks a copy from a DataSource into a Machine
    """

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Enum(DataTransferJobState), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    data_source_id = db.Column(db.Integer, db.ForeignKey("data_source.id"))
    machine_id = db.Column(db.Integer, db.ForeignKey("machine.id"))
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    user = db.relationship("User", back_populates="data_transfer_jobs")
    data_source = db.relationship("DataSource", back_populates="data_transfer_jobs")
    machine = db.relationship("Machine", back_populates="data_transfer_jobs")


class Group(db.Model):
    """
    A group that users belong to. A user can belong to a single group

    The group determines which MachineTemplates a user can see.
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    users = db.relationship("User", back_populates="group")
    machine_templates = db.relationship("MachineTemplate", back_populates="group")


class MachineTemplate(db.Model):
    """
    A MachineTemplate is a template from which the user builds Machines
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    memory_limit_gb = db.Column(db.Integer, nullable=True)
    cpu_limit_cores = db.Column(db.Integer, nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))

    group = db.relationship("Group", back_populates="machine_templates")
    machines = db.relationship("Machine", back_populates="machine_template")


class MachineState(enum.Enum):
    PROVISIONING = "P"
    READY = "R"
    FAILED = "F"
    DELETING = "D"
    DELETED = "DD"


class Machine(db.Model):
    """
    A Machine represents a container or virtual machine that the user
    uses.
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    token = db.Column(db.String(16), nullable=False, default=lambda: gen_token(16))
    state = db.Column(db.Enum(MachineState), nullable=False, index=True)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    machine_template_id = db.Column(db.Integer, db.ForeignKey("machine_template.id"))

    owner = db.relationship(
        "User", back_populates="owned_machines", foreign_keys=[owner_id]
    )
    shared_users = db.relationship(
        "User", secondary=shared_user_machine, back_populates="shared_machines"
    )
    machine_template = db.relationship("MachineTemplate", back_populates="machines")
    data_transfer_jobs = db.relationship("DataTransferJob", back_populates="machine")


# This is used in base.jinja2 to build the side bar menu
MAIN_MENU = [
    {
        "icon": "house",
        "name": "Welcome page",
        "href": "/",
    },
    {
        "icon": "server",
        "name": "Machines",
        "href": "/machines",
    },
    {
        "icon": "database",
        "name": "Data",
        "href": "/data",
    },
    {
        "icon": "book",
        "name": "Citations",
        "href": "/citations",
    },
    {
        "icon": "gear",
        "name": "Settings",
        "href": "/settings",
    },
    {
        "icon": "lightbulb",
        "name": "Help",
        "href": "/help",
    },
    {
        "icon": "circle-question",
        "name": "About",
        "href": "/about",
    },
]


def icon(text):
    """
    Return html for fontawesome icon - solid variant.
    """
    return f'<i class="fas fa-fw fa-{ text }"></i>'


def icon_regular(text):
    """
    Return html for fontawesome icon - regular variant.
    """
    return f'<i class="far fa-fw fa-{ text }"></i>'


def email(addr):
    """
    Return html for email link with fontawesome icon.
    """
    return (
        f'<a href="mailto:{ addr }"><i class="fas fa-fw fa-envelope"></i> { addr }</a>'
    )


def external_link(addr, desc=None):
    """
    Return html for link with external-link fontawesome icon.
    """
    if not desc:
        desc = addr
    return f'<a target="_blank" href="{ addr }">{ desc } <i class="fas fa-fw fa-external-link"></i></a>'


def info(text, **kwargs):
    """
    Return html for paragraph with info icon and some text - accepts kwargs
    """
    paragraph = f'<p><i class="fas fa-fw fa-info-circle"></i> {text}</p>'
    return paragraph.format(**kwargs)


def idea(text, **kwargs):
    """
    Return html for paragraph with info lightbulb and some text - accepts kwargs
    """
    paragraph = f'<p><i class="fas fa-fw fa-lightbulb"></i> {text}</p>'
    return paragraph.format(**kwargs)


@app.errorhandler(403)
def forbidden_handler(e):
    t = "Access denied"
    m = "Sorry, you don't have access to that page or resource."

    return render_template("error.jinja2", message=m, title=t, code=403), 403


# 404 error handler
@app.errorhandler(404)
def notfound_handler(e):
    t = "Not found"
    m = "Sorry, that page or resource could not be found."

    return render_template("error.jinja2", message=m, title=t, code=404), 404


# 500 error handler
@app.errorhandler(500)
def applicationerror_handler(e):
    t = "Application error"
    m = "Sorry, the application encountered a problem."

    return render_template("error.jinja2", message=m, title=t, code=500), 500


@app.context_processor
def inject_globals():
    """Add some stuff into all templates."""
    return {
        "icon": icon,
        "icon_regular": icon_regular,
        "email": email,
        "external_link": external_link,
        "info": info,
        "idea": idea,
        "main_menu": MAIN_MENU,
        "humanize": humanize,
    }


@login_manager.user_loader
def load_user(user_id):
    """
    This is called by flask-login on every request to load the user
    """
    return User.query.filter_by(id=int(user_id)).first()


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login page and login logic
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.jinja2", form=form)


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("welcome"))
    else:
        return redirect(url_for("login"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/welcome")
@login_required
def welcome():
    return render_template("welcome.jinja2", title="Welcome page")


@app.route("/machines")
@login_required
def machines():
    """
    The machine page displays and controls the user's machines
    """
    return render_template(
        "machines.jinja2",
        title="Machines",
        MachineTemplate=MachineTemplate,
        MachineState=MachineState,
        Machine=Machine,
        now=datetime.datetime.utcnow(),
        machine_format_dtj=machine_format_dtj,
    )


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.jinja2", title="Settings", threading=threading)


@app.route("/citations")
@login_required
def citations():
    return render_template("citations.jinja2", title="Citations")


@app.route("/about")
@login_required
def about():
    return render_template("about.jinja2", title="About")


@app.route("/help")
@login_required
def help():
    return render_template("help.jinja2", title="Help")


def encode_date_time(date_time):
    """
    Encode the date and time into a 6 character string
    """
    base_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base = len(base_chars)

    # Encode year, month, day, hour, minute, and second separately
    encoded_parts = []
    encoded_parts.append(
        base_chars[date_time.year % 100 // 4]
    )  # Encoded year (4-year granularity)
    encoded_parts.append(
        base_chars[date_time.month - 1]
    )  # Encoded month (0-based index)
    encoded_parts.append(base_chars[date_time.day - 1])  # Encoded day (0-based index)
    encoded_parts.append(base_chars[date_time.hour])  # Encoded hour
    encoded_parts.append(base_chars[date_time.minute])  # Encoded minute
    encoded_parts.append(base_chars[date_time.second])  # Encoded second

    # Combine encoded parts into a single string
    encoded_date_time = "".join(encoded_parts)
    return encoded_date_time


def mk_safe_machine_name(username):
    """
    We need a unique name in some circumstances, so we use the username
    and encoded datetime.

    This assumes the user doesn't want to make more than 1 machine
    per second
    """
    machine_name = username + "-" + encode_date_time(datetime.datetime.utcnow())
    return machine_name


@app.route("/register")
def register():
    return render_template("register.jinja2")


class DataTransferForm(FlaskForm):
    data_source = SelectField("Data Source", validators=[DataRequired()], coerce=int)
    machine = SelectField("Machine", validators=[DataRequired()], coerce=int)
    submit = SubmitField("Submit")


@app.route("/dismiss_datatransferjob", methods=["POST"])
def dismiss_datatransferjob():
    """
    Endpoint for hiding the data transfer job from the data page
    by setting its state to REMOVED
    """
    job_id = request.form.get("job_id")
    if not job_id:
        abort(404)

    job = DataTransferJob.query.filter_by(id=job_id).first_or_404()
    job.status = DataTransferJobState.REMOVED
    db.session.commit()
    return "OK"


def machine_format_dtj(machine):
    """
    Returns a set of unique formatted data transfer job entries for a specific machine.
    """
    Source = aliased(DataSource)
    jobs = (
        DataTransferJob.query.join(Source, DataTransferJob.data_source)
        .filter(DataTransferJob.machine == machine)
        .with_entities(Source.source_host, Source.source_dir)
        .distinct()
    )

    return {f"{source_host}:{source_dir}" for source_host, source_dir in jobs}


@app.route("/data", methods=["GET", "POST"])
def data():
    if current_user.is_admin:
        # the admin can see everything
        data_sources = DataSource.query.all()
        machines = Machine.query.filter_by(state=MachineState.READY)
    else:
        # a normal user can see their own stuff
        data_sources = current_user.data_sources
        machines = current_user.owned_machines + current_user.shared_machines

    # fill in the form select options
    form = DataTransferForm()
    form.data_source.choices = [
        (ds.id, f"{ds.source_host}:{ds.source_dir} ({ds.data_size} MB)")
        for ds in data_sources
    ]
    form.machine.choices = [
        (m.id, m.name) for m in machines if m.state == MachineState.READY
    ]

    if form.validate_on_submit():
        machine = Machine.query.filter_by(id=form.machine.data).first()
        data_source = DataSource.query.filter_by(id=form.data_source.data).first()

        if not machine or not data_source:
            abort(404)

        if machine not in machines or data_source not in data_sources:
            abort(403)

        # security checks ok

        job = DataTransferJob(
            status=DataTransferJobState.RUNNING,
            user=current_user,
            data_source=data_source,
            machine=machine,
        )
        db.session.add(job)
        db.session.commit()

        threading.Thread(target=start_data_transfer, args=(job.id,)).start()

        flash("Starting data transfer. Refresh page to update the status.")
        return redirect(url_for("data"))

    return render_template(
        "data.jinja2",
        title="Data",
        form=form,
        DataTransferJobState=DataTransferJobState,
        MachineState=MachineState,
    )


def do_rsync(source_host, source_dir, dest_host, dest_dir):
    try:
        # Construct the rsync command
        rsync_cmd = (
            f"rsync -avz -e 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' "
            f"{source_dir} {dest_host}:{dest_dir}"
        )
        logging.info(rsync_cmd)

        # Construct the ssh command to run the rsync command on the source_host
        ssh_cmd = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f'{source_host} "{rsync_cmd}"'
        )
        logging.info(ssh_cmd)

        # Execute the ssh command
        subprocess.run(ssh_cmd, shell=True, check=True, stderr=subprocess.PIPE)

        logging.info("Data transfer completed successfully.")
        return True

    except Exception as e:
        logging.exception("Error occurred during data transfer: ")
        return False


def start_data_transfer(job_id):
    """
    Thread function that takes a job and runs the data transfer
    """
    with app.app_context():
        job = DataTransferJob.query.filter_by(id=job_id).first()

        result = do_rsync(
            "dv@" + job.data_source.source_host,
            job.data_source.source_dir,
            "ubuntu@" + job.machine.ip,
            "",
        )

        if result:
            job.status = DataTransferJobState.DONE
        else:
            job.status = DataTransferJobState.FAILED
        db.session.commit()


@app.route("/new_machine", methods=["POST"])
@login_required
def new_machine():
    """
    Launches thread to create the container/vm
    """
    machine_template_name = request.form.get("machine_template_name", "")

    machine_name = mk_safe_machine_name(current_user.name)

    mt = MachineTemplate.query.filter_by(name=machine_template_name).first_or_404()

    m = Machine(
        name=machine_name,
        ip="",
        state=MachineState.PROVISIONING,
        owner=current_user,
        shared_users=[],
        machine_template=mt,
    )
    db.session.add(m)
    db.session.commit()

    logging.warning("starting new machine thread")

    if mt.type == "docker":
        threading.Thread(target=docker_start_container, args=(m.id, mt.id)).start()
    elif mt.type == "libvirt":
        threading.Thread(target=libvirt_start_vm, args=(m.id, mt.id)).start()

    flash(
        "Creating machine in the background. Refresh page to update status.",
        category="success",
    )
    return redirect(url_for("machines"))


@app.route("/share_machine/<machine_id>")
def share_machine(machine_id):
    """
    Shows the share page
    """
    machine_id = int(machine_id)
    machine = Machine.query.filter_by(id=machine_id).first_or_404()

    return render_template("share.jinja2", machine=machine)


@app.route("/share_accept/<machine_token>")
def share_accept(machine_token):
    """
    This is the endpoint hit by the user accepting a share
    """
    machine = Machine.query.filter_by(token=machine_token).first_or_404()
    if current_user == machine.owner:
        flash("You own that machine.")
        return redirect(url_for("machines"))
    if current_user in machine.shared_users:
        flash("You already have that machine.")
        return redirect(url_for("machines"))

    machine.shared_users.append(current_user)
    db.session.commit()
    flash("Shared machine has been added to your account.")
    return redirect(url_for("machines"))


@app.route("/share_revoke/<machine_id>")
def share_revoke(machine_id):
    """
    The owner revokes all shares. We do this by removing shared_users
    and resetting the machine token
    """
    machine = Machine.query.filter_by(id=machine_id).first_or_404()
    if current_user != machine.owner:
        flash("You can't revoke shares on a machine you don't own.")
        return redirect(url_for("machines"))

    machine.token = gen_token(16)
    machine.shared_users = []
    db.session.commit()
    flash(
        "Shares for machine have been removed and a new share link has been generated"
    )
    return redirect(url_for("machines"))


def docker_get_ip(client, container_name, network):
    container = client.containers.get(container_name)
    maybe_ip = container.attrs["NetworkSettings"]["Networks"][network]["IPAddress"]
    return maybe_ip


def docker_wait_for_ip(client, container_name, network):
    while not (ip := docker_get_ip(client, container_name, network)):
        time.sleep(1)
    return ip


@app.route("/stop_machine", methods=["POST"])
def stop_machine():
    """
    Start thread to stop machine
    """

    # sanity checks
    machine_id = request.form.get("machine_id")
    if not machine_id:
        logging.warning(f"machine_id parameter missing: {machine_id}")
        abort(404)
    machine_id = int(machine_id)
    machine = Machine.query.filter_by(id=machine_id).first_or_404()
    if not current_user.is_admin or not current_user == machine.owner:
        logging.error(
            f"user {current_user.id} is not the owner of machine {machine_id} nor admin"
        )
        abort(403)
    if machine.state in [
        MachineState.PROVISIONING,
        MachineState.DELETED,
        MachineState.DELETING,
    ]:
        logging.warning(
            f"machine {machine_id} is not in correct state for deletion: {machine.state}"
        )
        abort(500)

    # good to go
    logging.info(f"deleting container with machine id {machine_id}")
    machine.state = MachineState.DELETING
    db.session.commit()

    if machine.machine_template.type == "docker":
        threading.Thread(target=docker_stop_container, args=(machine_id,)).start()
    elif machine.machine_template.type == "libvirt":
        threading.Thread(target=libvirt_stop_vm, args=(machine.name,)).start()

    flash("Deleting machine in the background", category="success")
    return redirect(url_for("machines"))


def docker_get_container_by_ip(ip_address):
    try:
        client = docker.from_env()
        network = client.networks.get("adanet")
        containers = network.containers

        # Search for the container with the specified IP address
        container = None
        for cont in containers:
            cont_ips = [
                x["IPAddress"]
                for x in cont.attrs["NetworkSettings"]["Networks"].values()
            ]
            if ip_address in cont_ips:
                container = cont
                break

        if container is None:
            logging.error("container with ip {ip_address} not found")
            return

        container_id = container.id
        container = client.containers.get(container_id)
        return container
    except docker.errors.APIError as e:
        logging.exception("Error getting container by IP address")
    except Exception as e:
        logging.exception("Error: Unknown error occurred")


def docker_stop_container(machine_id):
    with app.app_context():
        machine = Machine.query.filter_by(id=machine_id).first()
        machine_ip = machine.ip

    try:
        container = docker_get_container_by_ip(machine.ip)
        if container:
            container.stop()
    except docker.errors.APIError as e:
        logging.exception("Error: stopping and removing container")
    except Exception as e:
        logging.exception("Error: Unknown error occurred")

    with app.app_context():
        machine = Machine.query.filter_by(id=machine_id).first()
        machine.state = MachineState.DELETED
        db.session.commit()
    logging.info(f"deleted container with machine id {machine_id}")


def docker_start_container(m_id, mt_id):
    logging.warning("entered start_container thread")
    with app.app_context():
        try:
            m = Machine.query.filter_by(id=m_id).first()
            mt = MachineTemplate.query.filter_by(id=mt_id).first()
            cpu_cores = mt.cpu_limit_cores
            mem_limit_gb = mt.memory_limit_gb
            client = docker.from_env()

            cpu_period = 100000
            cpu_quota = int(cpu_period * cpu_cores)
            mem_limit = f"{mem_limit_gb * 1024}m"  # Convert GB to MB

            # Define container options, including CPU and memory limits
            container_options = {
                "name": m.name,
                "image": mt.image,
                "network": "adanet",
                "cpu_period": cpu_period,
                "cpu_quota": cpu_quota,
                "mem_limit": mem_limit,
            }
            print(json.dumps(container_options, indent=4))

            # Start the container
            container = client.containers.run(
                **container_options,
                detach=True,
            )

            m.ip = docker_wait_for_ip(client, m.name, "adanet")

            m.state = MachineState.READY
            db.session.commit()
        except:
            logging.exception("Error: ")
            try:
                container.stop()
            except:
                logging.exception("Error: ")
            try:
                container.remove()
            except:
                logging.exception("Error: ")

            m.state = MachineState.FAILED
            m.ip = ""
            db.session.commit()

    logging.warning("all done!")


def libvirt_get_vm_ip(vm_name):
    command = ["virsh", "domifaddr", vm_name]
    result = subprocess.run(command, capture_output=True)
    output = result.stdout.decode("utf-8")
    lines = output.split("\n")
    for line in lines:
        if "ipv4" in line:
            parts = line.split()
            return parts[3].split("/")[0]
    return None


def libvirt_wait_for_ip(vm_name):
    while not (ip := libvirt_get_vm_ip(vm_name)):
        time.sleep(1)
    return ip


def libvirt_wait_for_vm(vm_name):
    # Wait for the virtual machine to be in the running state
    while True:
        output = subprocess.check_output(["virsh", "domstate", vm_name]).decode()
        if "running" in output:
            print(f"Virtual machine {vm_name} is now running")
            break
        time.sleep(1)


def libvirt_start_vm(m_id, mt_id):
    logging.info("entered start_libvirt_vm thread")
    with app.app_context():
        m = Machine.query.filter_by(id=m_id).first()
        mt = MachineTemplate.query.filter_by(id=mt_id).first()

        name = m.name
        image = mt.image
        cores = mt.cpu_limit_cores
        mem = int(mt.memory_limit_gb) * 1024 * 1024

        # clone vm
        subprocess.run(
            ["virt-clone", "--original", image, "--name", name, "--auto-clone"]
        )

        # Set the CPU and memory limits
        subprocess.run(["virsh", "setvcpus", name, str(cores), "--config", "--maximum"])
        subprocess.run(["virsh", "setvcpus", name, str(cores), "--config"])
        subprocess.run(["virsh", "setmaxmem", name, str(mem), "--config"])
        subprocess.run(["virsh", "setmem", name, str(mem), "--config"])

        # start vm
        subprocess.run(["virsh", "start", name])

        libvirt_wait_for_vm(name)
        ip = libvirt_wait_for_ip(name)

        m.ip = ip
        m.state = MachineState.READY
        db.session.commit()


def libvirt_stop_vm(vm_name):
    # Stop the virtual machine
    subprocess.run(["virsh", "destroy", vm_name])

    # Delete the disk
    subprocess.run(["virsh", "undefine", vm_name, "--remove-all-storage"])

    print(f"Stopped virtual machine {vm_name} and deleted its disk")


def create_initial_db():
    with app.app_context():
        if not User.query.filter_by(name="admin").first():
            logging.warning("Creating default data. First user is admin/admin.")
            demo_source1 = DataSource(
                source_host="localhost",
                source_dir="/tmp/demo1",
                data_size="123",
            )
            demo_source2 = DataSource(
                source_host="localhost",
                source_dir="/tmp/demo2",
                data_size="321",
            )
            demo_source3 = DataSource(
                source_host="localhost",
                source_dir="/tmp/demo3",
                data_size="432",
            )

            admin_group = Group(name="admins")
            normal_user_group = Group(name="XRAY scientists")
            admin_user = User(
                name="admin",
                group=admin_group,
                is_admin=True,
                email="denis.volk@stfc.ac.uk",
                data_sources=[demo_source1, demo_source2],
            )
            admin_user.set_password("admin")
            normal_user = User(
                name="xrayscientist",
                group=normal_user_group,
                email="xrays.smith@llnl.gov",
                data_sources=[demo_source2, demo_source3],
            )
            normal_user.set_password("xrayscientist")

            test_machine_template1 = MachineTemplate(
                name="Muon analysis template",
                type="libvirt",
                memory_limit_gb=16,
                cpu_limit_cores=4,
                image="debian11-5",
                group=admin_group,
                description="This is a libvirt machine template that's added by default when you're running in debug mode. It references the image \"debian11-5\"",
            )
            test_machine_template2 = MachineTemplate(
                name="XRAY analysis template",
                type="docker",
                memory_limit_gb=16,
                cpu_limit_cores=4,
                image="workspace",
                group=normal_user_group,
                description="This is a docker machine template that's added by default when you're running in debug mode. It references the image \"workspace\"",
            )

            test_machine1 = Machine(
                name="XRAY failed test",
                ip="",
                state=MachineState.FAILED,
                owner=normal_user,
                shared_users=[admin_user],
                machine_template=test_machine_template2,
            )

            db.session.add(admin_group)
            db.session.add(admin_user)
            db.session.add(normal_user_group)
            db.session.add(normal_user)
            db.session.add(test_machine_template1)
            db.session.add(test_machine_template2)
            db.session.add(test_machine1)
            db.session.commit()


def main(debug=False):
    # add an admin user and test machinetemplate and machine
    create_initial_db()

    app.run(debug=debug)


if __name__ == "__main__":
    argh.dispatch_command(main)
