import logging
import datetime
import enum
import threading
import time
import json
import string
import secrets

import argh
from flask import Flask, render_template, url_for, redirect, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
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
from werkzeug.exceptions import HTTPException
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
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


def gen_token(length):
    """
    Generate a cryptographically secure alphanumeric string of the given length.
    """
    alphabet = string.ascii_letters + string.digits
    secure_string = "".join(secrets.choice(alphabet) for _ in range(length))
    return secure_string


class User(db.Model, UserMixin):
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    users = db.relationship("User", back_populates="group")
    machine_templates = db.relationship("MachineTemplate", back_populates="group")


class MachineTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    memory_limit_gb = db.Column(db.String(16), nullable=True)
    cpu_limit_cores = db.Column(db.String(16), nullable=True)
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
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    token = db.Column(db.String(16), nullable=False, default=lambda: gen_token(16))
    state = db.Column(db.Enum(MachineState), nullable=False)
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
def forbidden(e):
    t = "Access denied"
    m = "Sorry, you don't have access to that page or resource."

    return render_template("error.jinja2", message=m, title=t, code=403), 403


# 404 error handler
@app.errorhandler(404)
def forbidden(e):
    t = "Not found"
    m = "Sorry, that page or resource could not be found."

    return render_template("error.jinja2", message=m, title=t, code=404), 404


# 500 error handler
@app.errorhandler(500)
def forbidden(e):
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
    return User.query.filter_by(id=int(user_id)).first()


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


@app.route("/login", methods=["GET", "POST"])
def login():
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
    return render_template(
        "machines.jinja2",
        title="Machines",
        MachineTemplate=MachineTemplate,
        MachineState=MachineState,
        Machine=Machine,
        now=datetime.datetime.utcnow(),
    )


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.jinja2", title="Settings")


def mk_safe_machine_name(username):
    machine_name = username + "_" + datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    machine_name = machine_name.replace(" ", "_")
    machine_name = "".join([c for c in machine_name if c.isalnum() or c == "_"])
    return machine_name


@app.route("/register")
def register():
    return render_template("register.jinja2")


@app.route("/new_machine", methods=["POST"])
@login_required
def new_machine():
    machine_template_name = request.form.get(
        "machine_template_name", "Muon analysis template"
    )

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

    logging.warning("starting thread")
    threading.Thread(target=start_container, args=(m.id, mt.id)).start()
    flash(
        "Creating machine in the background. Refresh page to update status.",
        category="success",
    )
    return redirect(url_for("machines"))


@app.route("/share_machine/<machine_id>")
def share_machine(machine_id):
    machine_id = int(machine_id)
    machine = Machine.query.filter_by(id=machine_id).first_or_404()
    if not machine.ip:
        logging.warning(f"machine {machine_id} doesn't have an ip in the database")
        abort(404)

    return render_template("share.jinja2", machine=machine)


@app.route("/share_accept/<machine_token>")
def share_accept(machine_token):
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
    machine_id = request.form.get("machine_id")
    if not machine_id:
        logging.warning(f"machine {machine_id} not found")
        abort(404)
    machine_id = int(machine_id)
    machine = Machine.query.filter_by(id=machine_id).first_or_404()
    if current_user != machine.owner:
        logging.warning(
            f"user {current_user.id} is not the owner of machine {machine_id}"
        )
        abort(403)
    if not machine.ip:
        logging.warning(f"machine {machine_id} doesn't have an ip in the database")
        abort(404)
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

    threading.Thread(target=stop_container, args=(machine_id,)).start()
    flash("Deleting machine in the background", category="success")
    return redirect(url_for("machines"))


def get_container_by_ip(ip_address):
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


def stop_container(machine_id):
    with app.app_context():
        machine = Machine.query.filter_by(id=machine_id).first_or_404()
        machine_ip = machine.ip

    try:
        container = get_container_by_ip(machine.ip)
        if not container:
            with app.app_context():
                abort(404)
        container.stop()
    except docker.errors.APIError as e:
        logging.exception("Error stopping and removing container")
        abort(500)
    except Exception as e:
        logging.exception("Error: Unknown error occurred")
        abort(500)

    with app.app_context():
        machine = Machine.query.filter_by(id=machine_id).first_or_404()
        machine.state = MachineState.DELETED
        db.session.commit()
    logging.info(f"deleted container with machine id {machine_id}")


def start_container(m_id, mt_id):
    logging.warning("entered thread")
    with app.app_context():
        try:
            m = Machine.query.filter_by(id=m_id).first()
            mt = MachineTemplate.query.filter_by(id=mt_id).first()
            client = docker.from_env()

            # Define container options, including CPU and memory limits
            container_options = {
                "name": m.name,
                "image": mt.image,
                "network": "adanet",
            }

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


def create_initial_db():
    with app.app_context():
        if not User.query.filter_by(name="admin").first():
            logging.warning("Creating default data. First user is admin/admin.")
            admin_group = Group(name="admins")
            normal_user_group = Group(name="XRAY scientists")
            admin_user = User(
                name="admin",
                group=admin_group,
                is_admin=True,
                email="denis.volk@stfc.ac.uk",
            )
            admin_user.set_password("admin")
            normal_user = User(
                name="xrayscientist",
                group=normal_user_group,
                email="xrays.smith@llnl.gov",
            )
            normal_user.set_password("xrayscientist")

            test_machine_template1 = MachineTemplate(
                name="Muon analysis template",
                type="docker",
                memory_limit_gb="16",
                cpu_limit_cores="4",
                image="workspace",
                group=admin_group,
                description="This is a machine template that's added by default when you're running in debug mode. It references the image \"workspace\"",
            )
            test_machine_template2 = MachineTemplate(
                name="XRAY analysis template",
                type="docker",
                memory_limit_gb="16",
                cpu_limit_cores="4",
                image="workspace",
                group=normal_user_group,
                description="This is a machine template that's added by default when you're running in debug mode. It references the image \"workspace\"",
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
