# python lib imports
import logging
import datetime
import enum
import threading
import time
import json
import string
import secrets
import subprocess
import functools
import inspect
import uuid
import socket
import os
import shlex
from abc import ABC, abstractmethod
import re
import html
import hashlib
from functools import cache
import collections

# flask and related imports
from flask import (
    Flask,
    render_template,
    url_for,
    redirect,
    flash,
    request,
    abort,
    has_request_context,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import aliased
from sqlalchemy import Index, JSON, desc, and_, or_, union, asc
from flask_migrate import Migrate
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask_admin.actions import action
from flask_admin.form import Select2Field
from flask_admin.contrib.sqla import ModelView
from flask_admin.model import typefmt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
from wtforms.widgets import TextArea
from wtforms import (
    StringField,
    PasswordField,
    SelectField,
    TextAreaField,
    SubmitField,
    HiddenField,
    Form,
)
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo
from flask_babel import Babel, gettext, lazy_gettext, _, Locale
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup
import waitress
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
import jinja2
from flask_mail import Mail, Message
from itsdangerous.url_safe import URLSafeTimedSerializer

# flask recaptcha uses jinja2.Markup, which doesn't exist any more,
# so we monkey-patch to use markupsafe.Markup
jinja2.Markup = Markup
from flask_recaptcha import ReCaptcha

# virtualization interfaces
import docker
import libvirt
import openstack
from cinderclient import client as cinderclient

# other 3rd party imports
import argh
import humanize
import pytz
import requests
import paramiko

# sentry.io integration
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.logging import LoggingIntegration

import misc.dnscrypto
import keys


def str_to_bool(s):
    return s and s.strip().lower() == "true"


logging.basicConfig(
    level=logging.DEBUG,
    datefmt="%Y-%m-%d/%H:%M:%S",
    format="%(asctime)s %(message)s",
)


# Only initialize Sentry if the DSN is present
if os.getenv("ADA2025_SENTRY_DSN"):
    sentry_logging = LoggingIntegration(
        level=logging.INFO,  # Capture info and above as breadcrumbs
        event_level=logging.ERROR,  # Send errors as events
    )

    sentry_sdk.init(
        dsn=os.getenv("ADA2025_SENTRY_DSN"),
        integrations=[
            FlaskIntegration(),
            SqlalchemyIntegration(),
            sentry_logging,
        ],
        environment=os.getenv("ADA2025_SENTRY_ENVIRONMENT", "development"),
        traces_sample_rate=0.01,
    )

try:
    cmd = "git describe --tags --always --dirty"
    version = subprocess.check_output(shlex.split(cmd)).decode().strip()
except:
    logging.exception("Couldn't get git version: ")
    version = ""

try:
    cmd = "hostname"
    hostname = subprocess.check_output(shlex.split(cmd)).decode().strip()
except Exception:
    logging.exception("Couldn't get hostname: ")
    hostname = ""


def gen_token(length):
    """
    Generate a cryptographically secure alphanumeric string of the given length.
    """
    alphabet = string.ascii_letters + string.digits
    secure_string = "".join(secrets.choice(alphabet) for _ in range(length))
    return secure_string


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("ADA2025_FLASK_SECRET_KEY") or gen_token(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "ADA2025_SQLALCHEMY_URL", "sqlite:///app.db"
)
app.config["FLASK_ADMIN_FLUID_LAYOUT"] = True
app.config["FLASK_ADMIN_SWATCH"] = "journal"
logging.info(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"

used_email_login_tokens = []
ADA2025_EMAIL_LOGIN_SECRET_KEY = os.getenv(
    "ADA2025_EMAIL_LOGIN_SECRET_KEY"
) or gen_token(32)

ADA2025_SHARE_TOKEN_SECRET_KEY = os.getenv(
    "ADA2025_SHARE_TOKEN_SECRET_KEY"
) or gen_token(32)

ADA2025_DNS_SECRET_KEY = os.getenv("ADA2025_DNS_SECRET_KEY") or gen_token(32)

admin = Admin(
    url="/flaskyadmin",
    template_mode="bootstrap4",
)
admin.init_app(app)


def get_limiter_key():
    if current_user.is_authenticated:
        return current_user.username
    else:
        return request.remote_addr


limiter = Limiter(
    # no default limit because flask-admin trips it up
    # instead we put 60 per minute on all requests, except
    # /login and /register, which have 60 per hour
    app=app,
    key_func=get_limiter_key,
    storage_uri="memory://",
    strategy="moving-window",
)

recaptcha = ReCaptcha(
    site_key=os.environ.get("RECAPTCHA_SITE_KEY"),
    secret_key=os.environ.get("RECAPTCHA_SECRET_KEY"),
    is_enabled=True if os.environ.get("RECAPTCHA_SITE_KEY") else False,
)
recaptcha.init_app(app)
LOGIN_RECAPTCHA = str_to_bool(os.environ.get("LOGIN_RECAPTCHA"))


app.config["MAIL_SERVER"] = os.environ.get("ADA2025_MAIL_SERVER", "")
app.config["MAIL_PORT"] = os.environ.get("ADA2025_MAIL_PORT", 465)
app.config["MAIL_USERNAME"] = os.environ.get("ADA2025_MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("ADA2025_MAIL_PASSWORD", "")
app.config["MAIL_USE_TLS"] = str_to_bool(
    os.environ.get("ADA2025_MAIL_USE_TLS", "False")
)
app.config["MAIL_USE_SSL"] = str_to_bool(os.environ.get("ADA2025_MAIL_USE_SSL", "True"))
MAIL_SENDER = os.environ.get("ADA2025_MAIL_SENDER", "")
mail = Mail(app)


@app.before_request
def before_request():
    if current_user.is_authenticated:
        # send to sentry.io on captured errors
        sentry_sdk.set_user(
            {
                "id": current_user.id,
                "sesh_id": current_user.sesh_id,
            }
        )
    else:
        # no user is logged in
        sentry_sdk.set_user(None)


# change the number of rows in flask-admin modelviews textareas
class CustomTextAreaWidget(TextArea):
    def __init__(self, rows=15):
        self.rows = rows

    def __call__(self, field, **kwargs):
        kwargs.setdefault("rows", self.rows)
        return super(CustomTextAreaWidget, self).__call__(field, **kwargs)


class BigTextAreaField(TextAreaField):
    def __init__(self, label=None, validators=None, rows=15, **kwargs):
        super(BigTextAreaField, self).__init__(label, validators, **kwargs)
        self.widget = CustomTextAreaWidget(rows)


# for nicer formatting of json data in flask-admin forms
class JsonTextAreaField(TextAreaField):
    widget = CustomTextAreaWidget()

    def __init__(self, label=None, validators=None, rows=10, **kwargs):
        super(JsonTextAreaField, self).__init__(label, validators, **kwargs)
        self.widget = CustomTextAreaWidget(rows)

    def process_formdata(self, valuelist):
        if valuelist:
            value = valuelist[0]
            if value:
                try:
                    self.data = json.loads(value)
                except ValueError:
                    self.data = None
                    raise ValueError(self.gettext("Invalid JSON data."))
            else:
                self.data = None
        else:
            self.data = None

    def _value(self):
        if self.data is not None:
            return json.dumps(self.data, indent=4)
        else:
            return ""


# make the flask-admin interface only accessible to admins
class ProtectedModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for("login"))

    # since we're here, add an option to clone rows
    @action(
        "clone", "Clone", "Are you sure you want to create a copy of the selected rows?"
    )
    def action_clone(self, ids):
        try:
            for id in ids:
                record = self.get_one(id)
                if record is not None:
                    clone = self._create_clone(record)
                    self.session.add(clone)
            self.session.commit()
            flash(f"Successfully created a copy of {len(ids)} records.")
        except Exception as ex:
            if not self.handle_view_exception(ex):
                raise
            flash("Failed to clone record. %(error)s", "error", error=str(ex))

    def _create_clone(self, record):
        clone = self.model()
        for field in self._get_field_names():
            if field != "id":
                setattr(clone, field, getattr(record, field))
        return clone

    def _get_field_names(self):
        return self.model.__table__.columns.keys()

    # since we're here, change the date fomat to humanize naturaldelta
    column_type_formatters = dict(typefmt.BASE_FORMATTERS)
    column_type_formatters.update(
        {
            datetime.datetime: lambda view, value: humanize.naturaldelta(
                datetime.datetime.utcnow() - value
            )
            + " ago"
        }
    )
    # since we're here... sort by id desc
    column_default_sort = ("id", True)


socket.setdefaulttimeout(5)


def get_hostname(ip):
    # get the hostname of an ip
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        logging.warning(f"Couldn't get hostname of {ip}")
        return ""


thread_id_map = {}
thread_id_counter = 0
thread_id_lock = threading.Lock()


# make a small thread id for logging
def get_small_thread_id():
    global thread_id_counter, thread_id_map, thread_id_lock
    thread_id = threading.get_ident()
    with thread_id_lock:
        if thread_id not in thread_id_map:
            thread_id_map[thread_id] = thread_id_counter
            thread_id_counter += 1
    return thread_id_map[thread_id]


# decorator for functions that logs some stuff
def log_function_call(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        function_signature = inspect.signature(func)
        bound_arguments = function_signature.bind(*args, **kwargs)
        bound_arguments.apply_defaults()

        call_uuid = uuid.uuid4().hex[:8]  # Generate a short unique ID
        small_thread_id = get_small_thread_id()  # Get a small, unique thread ID
        logging.info(
            f"[{call_uuid}-{small_thread_id}] Entering function '{func.__name__}' with bound arguments {bound_arguments.arguments}"
        )

        result = func(*args, **kwargs)

        elapsed_time = time.perf_counter() - start_time
        logging.info(
            f"[{call_uuid}-{small_thread_id}] Exiting function '{func.__name__}' after {elapsed_time:.6f} seconds"
        )
        return result

    return wrapper


def is_name_safe(display_name):
    # Disallow <, >, &, /, \, and ;
    blacklist = re.compile(r"[<>&/\\;]")

    return not bool(blacklist.search(display_name))


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

colors = [
    "crimson",
    "indigo",
    "purple",
    "salmon",
    "seagreen",
    "sandybrown",
    "slategray",
    "teal",
    "steelblue",
    "chocolate",
    "darkcyan",
    "darkgoldenrod",
    "darkkhaki",
    "darkorange",
    "darkseagreen",
    "dodgerblue",
    "orchid",
    "royalblue",
    "slateblue",
    "yellowgreen",
]


@cache
# pick a bootstrap color for coloring flask-admin table cells
def color(name):
    # Create a hash object
    h = hashlib.md5()

    # Add the name to the hash object
    h.update(name.encode())

    # Get the hash of the name as an integer
    name_hash = int(h.hexdigest(), 16)

    # Use the hash to pick a color
    color_code = colors[name_hash % len(colors)]

    return color_code


# a formatter for flask-admin modelview cells that picks a background color
# based on the name of the field. handles foreign keys too
def _color_formatter(view, context, model, name):
    # Check if this is a field of a related model
    if "." in name:
        # Split the name into the relation name and the field name
        relation_name, field_name = name.split(".", 1)
        # Get the related model
        related_model = getattr(model, relation_name)
        # Get the value of the __repr__ of the related model
        attr_value = str(related_model) if related_model else ""
    else:
        # This is a field of the model itself
        attr_value = str(getattr(model, name))
        if attr_value == "None":
            return Markup("")

    # Escape the special HTML characters
    attr_value_escaped = html.escape(attr_value)

    color_code = color(attr_value_escaped)
    return Markup(
        '<div class="rounded pl-2 pr-2" style="color: #fff; background-color: {0}; text-align: center;">{1}</div>'.format(
            color_code, attr_value_escaped
        )
    )


# a formatter for flask-admin modelview cells that picks background colors
# for a field that's a comma-sep list of items
def _list_color_formatter(view, context, model, name):
    # This is a field of the model itself
    attr_value = str(getattr(model, name))
    if attr_value == "None":
        return Markup("")

    # Escape the special HTML characters
    attr_value_escaped = html.escape(attr_value)

    xs = attr_value_escaped[1:-1].split(",")
    if not xs or xs == [""]:
        return Markup("")
    out = ""
    for x in xs:
        color_code = color(x)
        out += '<span class="rounded p-1 mr-1" style="color: #fff; background-color: {0};">{1}</span>'.format(
            color_code, x
        )
    return Markup(out)


class Group(db.Model):
    """
    A group that users belong to. A user can belong to a single group

    The group determines which MachineTemplates a user can see.
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    is_public = db.Column(db.Boolean(), nullable=False, default=False)

    users = db.relationship("User", back_populates="group")
    machine_templates = db.relationship("MachineTemplate", back_populates="group")
    welcome_page = db.relationship("GroupWelcomePage", backref="group", uselist=False)

    def __repr__(self):
        return f"<{self.name}>"


class ProtectedGroupModelView(ProtectedModelView):
    column_list = (
        "id",
        "name",
        "creation_date",
        "is_public",
        "users",
        "machine_templates",
        "welcome_page",
    )
    form_columns = (
        "name",
        "creation_date",
        "is_public",
        "users",
        "machine_templates",
        "welcome_page",
    )
    column_searchable_list = ("name",)
    column_sortable_list = ("id", "name", "creation_date")
    column_filters = ("name", "is_public", "creation_date")
    column_auto_select_related = True
    column_formatters = {
        "users": _list_color_formatter,
        "machine_templates": _list_color_formatter,
    }


class GroupWelcomePage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    format = db.Column(db.String(16), nullable=False, default="html")
    content = db.Column(db.Text)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    updated_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    def __repr__(self):
        return f"<GWP {self.id}>"


class ProtectedGroupWelcomePageModelView(ProtectedModelView):
    column_list = ("id", "updated_date", "format", "group_id")
    form_columns = ("updated_date", "group_id", "format", "content")
    column_searchable_list = ("group_id",)
    column_sortable_list = ("id", "updated_date", "group_id")
    column_auto_select_related = True
    form_extra_fields = {"content": BigTextAreaField("Content", rows=25)}


def gen_ssh_keys(user_id):
    private_key, public_key = keys.generate_user_keys(str(user_id))
    return SSHKeys(private_key=private_key, public_key=public_key, authorized_keys="")


class SSHKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    private_key = db.Column(db.Text)
    public_key = db.Column(db.Text)
    authorized_keys = db.Column(db.Text)

    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    owner = db.relationship("User", back_populates="ssh_keys")


class User(db.Model, UserMixin):
    """
    User model, also used for flask-login
    """

    id = db.Column(db.Integer, primary_key=True)
    # small token generated every time a User object is created
    sesh_id = db.Column(db.String(2), nullable=False, default=lambda: gen_token(2))
    is_enabled = db.Column(db.Boolean, nullable=False, default=False)
    is_banned = db.Column(db.Boolean, nullable=False, default=False)
    is_group_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    given_name = db.Column(db.String(100))
    family_name = db.Column(db.String(100))
    organization = db.Column(db.String(200))
    job_title = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True, nullable=False)
    language = db.Column(db.String(5), default="en", nullable=False)
    timezone = db.Column(db.String(50), default="Europe/London", nullable=False)

    # oauth2 stuff
    provider = db.Column(db.String(64))  # e.g. 'google', 'local'
    provider_id = db.Column(db.String(64))  # e.g. Google's unique ID for the user

    extra_data = db.Column(db.JSON, default={})

    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    group = db.relationship("Group")

    owned_machines = db.relationship(
        "Machine", back_populates="owner", foreign_keys="Machine.owner_id"
    )
    shared_machines = db.relationship(
        "Machine", secondary=shared_user_machine, back_populates="shared_users"
    )
    data_sources = db.relationship(
        "DataSource", secondary=user_data_source_association, back_populates="users"
    )
    ssh_keys = db.relationship("SSHKeys", uselist=False, back_populates="owner")

    data_transfer_jobs = db.relationship("DataTransferJob", back_populates="user")
    problem_reports = db.relationship("ProblemReport", back_populates="user")
    audit_events = db.relationship("Audit", back_populates="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<{self.username}>"


class AssignDataSourcesForm(FlaskForm):
    data_sources = QuerySelectMultipleField(
        "Data Sources", query_factory=lambda: DataSource.query.all()
    )
    submit = SubmitField("Assign Data Sources")


class ProtectedAssignDataSourcesView(BaseView):
    def is_visible(self):
        return False

    @expose("/", methods=("GET", "POST"))
    def index(self):
        if not current_user or not current_user.is_admin:
            return redirect("/")
        user_ids = request.args.getlist("id")
        users = User.query.filter(User.id.in_(user_ids)).all()

        form = AssignDataSourcesForm(request.form)

        if request.method == "GET":
            # Pre-select the existing data sources only if a single user is selected
            if len(users) == 1:
                form.data_sources.data = users[0].data_sources

        if request.method == "POST" and form.validate():
            for user in users:
                user.data_sources = form.data_sources.data
            db.session.commit()
            flash(f"Data sources were successfully assigned to the selected users.")
            return redirect(url_for("user.index_view"))
        return self.render("admin/assignDS.html", form=form)


class AddUserToGroupForm(Form):
    group = SelectField("Group", validators=[DataRequired()])
    submit = SubmitField("Add Users to Group")


class SetupUserForm(Form):
    group = SelectField("Group", validators=[DataRequired()])
    data_sources = QuerySelectMultipleField(
        "Data Sources", query_factory=lambda: DataSource.query.all()
    )
    submit = SubmitField("Setup User")


class ProtectedSetupUserView(BaseView):
    def is_visible(self):
        return False

    @expose("/", methods=("GET", "POST"))
    def index(self):
        if not current_user or not current_user.is_admin:
            return redirect("/")
        user_ids = request.args.getlist("id")
        users = User.query.filter(User.id.in_(user_ids)).all()

        form = SetupUserForm(request.form)
        form.group.choices = [(g.id, g.name) for g in Group.query.all()]

        if request.method == "GET":
            # Pre-select the existing data sources only if a single user is selected
            if len(users) == 1:
                form.data_sources.data = users[0].data_sources

        if request.method == "POST" and form.validate():
            group_id = form.group.data
            group = Group.query.get(group_id)
            for user in users:
                user.is_enabled = True
                user.group = group
                user.data_sources = form.data_sources.data
            db.session.commit()
            flash(f"User setup was successful.")
            return redirect(url_for("user.index_view"))

        return self.render("admin/setupuser.html", users=users, form=form)


class ProtectedAddUserToGroupView(BaseView):
    def is_visible(self):
        return False

    @expose("/", methods=("GET", "POST"))
    def index(self):
        if not current_user or not current_user.is_admin:
            return redirect("/")
        form = AddUserToGroupForm(request.form)
        form.group.choices = [(g.id, g.name) for g in Group.query.all()]

        if request.method == "POST" and form.validate():
            group_id = form.group.data
            user_ids = request.args.getlist("id")
            group = Group.query.get(group_id)
            users = User.query.filter(User.id.in_(user_ids)).all()
            for user in users:
                user.group = group
            db.session.commit()
            flash(f"Users were successfully added to the group {group.name}.")
            return redirect(url_for("user.index_view"))
        return self.render("admin/setgroup.html", form=form)


class ProtectedEnableAndAddUserToGroupView(BaseView):
    def is_visible(self):
        return False

    @expose("/", methods=("GET", "POST"))
    def index(self):
        if not current_user or not current_user.is_admin:
            return redirect("/")
        form = AddUserToGroupForm(request.form)
        form.group.choices = [(g.id, g.name) for g in Group.query.all()]
        if request.method == "POST" and form.validate():
            group_id = form.group.data
            user_ids = request.args.getlist("id")
            group = Group.query.get(group_id)
            users = User.query.filter(User.id.in_(user_ids)).all()
            for user in users:
                user.group = group
                user.is_enabled = True
            db.session.commit()
            flash(
                f"Users were successfully enabled and added to the group {group.name}."
            )
            return redirect(url_for("user.index_view"))
        return self.render("admin/setupuser.html", form=form)


class ProtectedUserModelView(ProtectedModelView):
    column_list = (
        "id",
        "is_enabled",
        "username",
        "provider",
        "given_name",
        "family_name",
        "email",
        "group",
        "is_admin",
        "creation_date",
    )
    form_columns = (
        "is_enabled",
        "is_banned",
        "is_group_admin",
        "group",
        "username",
        "password",
        "given_name",
        "family_name",
        "organization",
        "job_title",
        "language",
        "timezone",
        "email",
        "creation_date",
        "owned_machines",
        "shared_machines",
        "data_sources",
        "data_transfer_jobs",
        "is_admin",
        "provider",
        "provider_id",
    )
    column_searchable_list = ("username", "email")
    column_sortable_list = ("id", "username", "email", "creation_date")
    column_filters = ("is_enabled", "is_banned", "is_group_admin", "is_admin", "group")
    column_auto_select_related = True
    form_extra_fields = {"password": PasswordField("Password")}

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            model.set_password(form.password.data)

    column_formatters = {
        "is_enabled": _color_formatter,
        "is_admin": _color_formatter,
        "provider": _color_formatter,
        "group": _color_formatter,
    }

    def scaffold_form(self):
        form_class = super(ProtectedUserModelView, self).scaffold_form()
        form_class.extra_data = JsonTextAreaField("Extra Data")
        return form_class

    @action(
        "enable_user",
        "Enable User",
        "Are you sure you want to enable the selected users?",
    )
    def action_enable_user(self, ids):
        try:
            query = User.query.filter(User.id.in_(ids))

            count = 0
            for user in query.all():
                if not user.is_enabled:
                    user.is_enabled = True
                    count += 1

            self.session.commit()

            flash(f"{count} users were successfully enabled.")
        except Exception as ex:
            if not self.handle_view_exception(ex):
                raise

            flash(f"Failed to enable users. {str(ex)}", "error")

    @action(
        "disable_user",
        "Disable User",
        "Are you sure you want to disable the selected users?",
    )
    def action_disable_user(self, ids):
        try:
            query = User.query.filter(User.id.in_(ids))

            count = 0
            for user in query.all():
                if user.is_enabled:
                    user.is_enabled = False
                    count += 1

            self.session.commit()

            flash(f"{count} users were successfully disabled.")
        except Exception as ex:
            if not self.handle_view_exception(ex):
                raise

            flash(f"Failed to disable users. {str(ex)}", "error")

    @action(
        "add_to_group",
        "Add to Group",
        "Are you sure you want to add the selected users to a group?",
    )
    def action_add_to_group(self, ids):
        return redirect(url_for("addusertogroup.index", id=ids))

    @action(
        "enable_and_add_to_group",
        "Enable and add to Group",
        "Are you sure you want to enable the selected users and add them to a group?",
    )
    def action_enable_and_add_to_group(self, ids):
        return redirect(url_for("enableandaddusertogroup.index", id=ids))

    @action(
        "assign_data_sources",
        "Assign Data Sources",
        "Are you sure you want to assign data sources to the selected users?",
    )
    def action_assign_data_sources(self, ids):
        return redirect(url_for("assigndatasources.index", id=ids))

    @action(
        "setup_user", "Setup User", "Are you sure you want to setup the selected users?"
    )
    def action_setup_user(self, ids):
        return redirect(url_for("setupuser.index", id=ids))


class DataSource(db.Model):
    """
    The DataSource model represents a source of data for users that
    they can use to copy into their machine.

    This is done by SSHing into the source_host and then running
    rsync to sync the data into the machine ip.
    """

    id = db.Column(db.Integer, primary_key=True)
    import_name = db.Column(db.String(256), nullable=False)
    is_enabled = db.Column(db.Boolean, nullable=False, default=False)
    name = db.Column(db.String, unique=True, nullable=False)
    source_username = db.Column(db.String(64), nullable=False, default="root")
    source_host = db.Column(db.String(256), nullable=False)
    source_port = db.Column(db.Integer, nullable=False, default=22)
    source_dir = db.Column(db.String(256), nullable=False)
    data_size = db.Column(db.Integer, nullable=False)  # in MB
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    users = db.relationship(
        "User", secondary=user_data_source_association, back_populates="data_sources"
    )
    data_transfer_jobs = db.relationship(
        "DataTransferJob", back_populates="data_source"
    )

    def __repr__(self):
        return f"<{self.name}>"


class ProtectedDataSourceModelView(ProtectedModelView):
    column_list = (
        "id",
        "is_enabled",
        "name",
        "source_host",
        "source_dir",
        "data_size",
        "import_name",
        "creation_date",
        "users",
    )
    form_columns = (
        "name",
        "is_enabled",
        "import_name",
        "source_username",
        "source_host",
        "source_port",
        "source_dir",
        "data_size",
        "users",
        "data_transfer_jobs",
    )
    column_searchable_list = ("source_host", "source_dir", "import_name")
    column_sortable_list = (
        "id",
        "source_host",
        "data_size",
        "creation_date",
        "import_name",
    )
    column_filters = (
        "is_enabled",
        "import_name",
        "source_username",
        "source_host",
        "source_port",
        "source_dir",
        "data_size",
    )
    column_auto_select_related = True
    column_formatters = {
        "is_enabled": _color_formatter,
        "import_name": _color_formatter,
        "source_host": _color_formatter,
    }


Index("source_host_source_dir_idx", DataSource.source_host, DataSource.source_dir)


class DataTransferJobState(enum.Enum):
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"
    HIDDEN = "HIDDEN"


class DataTransferJob(db.Model):
    """
    The DataTransferJob tracks a copy from a DataSource into a Machine
    """

    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.Enum(DataTransferJobState), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    data_source_id = db.Column(db.Integer, db.ForeignKey("data_source.id"))
    machine_id = db.Column(db.Integer, db.ForeignKey("machine.id"))
    machine2_id = db.Column(db.Integer, db.ForeignKey("machine.id"))
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )

    user = db.relationship("User", back_populates="data_transfer_jobs")
    data_source = db.relationship("DataSource", back_populates="data_transfer_jobs")
    machine = db.relationship(
        "Machine", back_populates="data_transfer_jobs", foreign_keys=[machine_id]
    )
    machine2 = db.relationship(
        "Machine",
        back_populates="machine_transfer_dest_jobs",
        foreign_keys=[machine2_id],
    )
    problem_reports = db.relationship(
        "ProblemReport", back_populates="data_transfer_job"
    )
    audit_events = db.relationship("Audit", back_populates="data_transfer_job")

    def __repr__(self):
        return f"<Data {self.data_source_id}>"


class ProtectedDataTransferJobModelView(ProtectedModelView):
    column_list = (
        "id",
        "state",
        "user",
        "data_source",
        "machine",
        "creation_date",
    )
    form_columns = ("state", "user", "data_source", "machine")
    column_searchable_list = ("state",)
    column_sortable_list = ("id", "state", "creation_date")
    column_filters = ("state", "user", "data_source", "machine")
    column_auto_select_related = True
    column_formatters = {
        "state": _color_formatter,
        "user": _color_formatter,
        "machine": _color_formatter,
        "data_source": _color_formatter,
    }


class MachineProvider(db.Model):
    """
    A machine provider is a local connection like local docker
    or external provider like openstack or cloud provider like aws
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    type = db.Column(db.String(100), nullable=False)
    customer = db.Column(db.String(100), nullable=False)
    provider_data = db.Column(JSON, default={}, nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    machine_templates = db.relationship(
        "MachineTemplate", back_populates="machine_provider"
    )

    def __repr__(self):
        if self.customer:
            return f"<{self.name} ({self.customer})>"
        else:
            return f"<{self.name}>"

    """
    based on experience, cloud providers have the following parameters:

    azure:
      resource_group: test
      instance_type: Standard_E8s_v3
      vm_image: UbuntuLTS
    openstack-1:
      flavor: climb.group
      network_uuid: 895d68df-6cff-45a1-9399-c10109b8bfbd
      key_name: denis
      vol_size: 120
      vol_image: e09bc162-1e18-447c-a577-e6b8af2cbc61
    gcp:
      zone: europe-west2-c
      image_family: ubuntu-1804-lts
      image_project: ubuntu-os-cloud
      machine_type: n1-highmem-4
      boot_disk_size: 120GB
    aws:
      image_id: ami-0c30afcb7ab02233d
      instance_type: r5.xlarge
      key_name: awstest
      security_group_id: sg-002bd90eab458665f
      subnet_id: subnet-ffd5a396
    oracle:
      compartment_id: ocid1.compartment.oc1..aaaaaaaao4kpjckz2pjmlc...
      availability_domain: LfHB:UK-LONDON-1-AD-1
      image_id: ocid1.image.oc1.uk-london-1.aaaaaaaaoc2hx6m45bba2av...
      shape: VM.Standard2.4
      subnet_id: ocid1.subnet.oc1.uk-london-1.aaaaaaaab3zsfqtkoyxtx...
      boot_volume_size_in_gbs: 120
    """


class ProtectedMachineProviderModelView(ProtectedModelView):
    column_list = ("id", "name", "type", "customer", "creation_date")
    column_searchable_list = ("name", "type", "customer")
    column_filters = ("name", "customer")

    form_columns = (
        "name",
        "type",
        "customer",
        "creation_date",
        "provider_data",
        "machine_templates",
    )
    column_auto_select_related = True

    # Custom formatter for provider_data
    def _provider_data_formatter(view, context, model, name):
        json_data = model.provider_data
        if not json_data:
            return ""
        formatted_data = [f"{k}: {v}" for k, v in json_data.items()]
        return Markup("<br>".join(formatted_data))

    column_formatters = {
        "provider_data": _provider_data_formatter,
        "type": _color_formatter,
        "customer": _color_formatter,
    }

    def scaffold_form(self):
        form_class = super(ProtectedMachineProviderModelView, self).scaffold_form()
        form_class.provider_data = JsonTextAreaField("Provider Data")
        return form_class


software_image_table = db.Table(
    "software_image",
    db.Column(
        "software_id", db.Integer, db.ForeignKey("software.id"), primary_key=True
    ),
    db.Column("image_id", db.Integer, db.ForeignKey("image.id"), primary_key=True),
)


image_provider_table = db.Table(
    "image_provider",
    db.Column("image_id", db.Integer, db.ForeignKey("image.id"), primary_key=True),
    db.Column(
        "machine_provider_id",
        db.Integer,
        db.ForeignKey("machine_provider.id"),
        primary_key=True,
    ),
)


class Software(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    images = db.relationship(
        "Image", secondary=software_image_table, backref="softwares"
    )

    def __repr__(self):
        return f"<{self.name}>"


class ProtectedSoftwareModelView(ProtectedModelView):
    column_list = ["name", "images", "creation_date"]
    form_excluded_columns = ["id"]  # Exclude 'id' from the form
    column_formatters = {
        "images": _list_color_formatter,
    }


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100))
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    machine_providers = db.relationship(
        "MachineProvider", secondary=image_provider_table, backref="images"
    )

    def __repr__(self):
        return f"<{self.name}>"


class ProtectedImageModelView(ProtectedModelView):
    column_list = [
        "name",
        "display_name",
        "softwares",
        "machine_providers",
        "machine_templates",
        "creation_date",
    ]
    form_excluded_columns = ["id"]  # Exclude 'id' from the form
    column_formatters = {
        "softwares": _list_color_formatter,
        "machine_templates": _list_color_formatter,
        "machine_providers": _list_color_formatter,
    }


class MachineTemplate(db.Model):
    """
    A MachineTemplate is a template from which the user builds Machines
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    os_username = db.Column(db.String(100), nullable=False)  # operating system username
    description = db.Column(db.String(200), nullable=True)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    memory_limit_gb = db.Column(db.Integer, nullable=True)
    cpu_limit_cores = db.Column(db.Integer, nullable=True)
    disk_size_gb = db.Column(db.Integer, nullable=True)
    image_id = db.Column(db.Integer, db.ForeignKey("image.id"))
    image = db.relationship("Image", backref="machine_templates")
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    group = db.relationship("Group", back_populates="machine_templates")
    machine_provider_id = db.Column(db.Integer, db.ForeignKey("machine_provider.id"))
    machine_provider = db.relationship(
        "MachineProvider", back_populates="machine_templates"
    )
    machines = db.relationship("Machine", back_populates="machine_template")
    extra_data = db.Column(db.JSON, default={})

    def __repr__(self):
        return f"<{self.name}>"


class ProtectedMachineTemplateModelView(ProtectedModelView):
    column_list = (
        "id",
        "name",
        "group",
        "type",
        "image",
        "memory_limit_gb",
        "cpu_limit_cores",
        "machine_provider",
    )
    form_columns = (
        "name",
        "type",
        "image",
        "os_username",
        "description",
        "cpu_limit_cores",
        "memory_limit_gb",
        "disk_size_gb",
        "group",
        "machine_provider",
        "machines",
        "extra_data",
    )
    column_searchable_list = ("name", "type")
    column_sortable_list = (
        "id",
        "name",
        "type",
        "creation_date",
        "memory_limit_gb",
        "cpu_limit_cores",
    )
    column_filters = ("type", "group")
    column_auto_select_related = True

    # Custom formatter for extra_data
    def _extra_data_formatter(view, context, model, name):
        json_data = model.extra_data
        if not json_data:
            return ""
        formatted_data = [f"{k}: {v}" for k, v in json_data.items()]
        return Markup("<br>".join(formatted_data))

    column_formatters = {
        "extra_data": _extra_data_formatter,
        "group": _color_formatter,
        "type": _color_formatter,
        "image": _color_formatter,
    }

    def scaffold_form(self):
        form_class = super(ProtectedMachineTemplateModelView, self).scaffold_form()
        form_class.extra_data = JsonTextAreaField("Extra Data")
        return form_class


class MachineState(enum.Enum):
    PROVISIONING = "PROVISIONING"
    READY = "READY"
    FAILED = "FAILED"
    DELETING = "DELETING"
    DELETED = "DELETED"
    STOPPED = "STOPPED"
    STOPPING = "STOPPING"
    STARTING = "STARTING"


class Machine(db.Model):
    """
    A Machine represents a container or virtual machine that the user
    uses.
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(45))
    hostname = db.Column(db.String(200), default="")
    share_token = db.Column(
        db.String(16), nullable=False, default=lambda: gen_token(16)
    )
    access_token = db.Column(
        db.String(16), nullable=False, default=lambda: gen_token(16)
    )
    state = db.Column(
        db.Enum(MachineState, native_enum=False), nullable=False, index=True
    )
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
    data_transfer_jobs = db.relationship(
        "DataTransferJob",
        foreign_keys=[DataTransferJob.machine_id],
        back_populates="machine",
    )
    machine_transfer_dest_jobs = db.relationship(
        "DataTransferJob",
        foreign_keys=[DataTransferJob.machine2_id],
        back_populates="machine2",
    )
    problem_reports = db.relationship("ProblemReport", back_populates="machine")
    audit_events = db.relationship("Audit", back_populates="machine")

    def __repr__(self):
        return f"<{self.display_name}>"

    def make_url(self):
        prefix = "http://"
        mt = self.machine_template
        ed = mt.extra_data
        if ed.get("has_https"):
            prefix = "https://"
        if self.hostname:
            return prefix + self.hostname
        else:
            return prefix + self.ip

    def make_access_url(self):
        return self.make_url() + "/" + self.access_token


class ProtectedMachineModelView(ProtectedModelView):
    column_list = (
        "id",
        "display_name",
        "ip",
        "hostname",
        "state",
        "creation_date",
        "owner",
        "machine_template",
        "screenshot",
    )
    form_columns = (
        "name",
        "display_name",
        "ip",
        "hostname",
        "state",
        "share_token",
        "access_token",
        "owner",
        "shared_users",
        "machine_template",
        "data_transfer_jobs",
    )
    column_searchable_list = (
        "name",
        "ip",
        "share_token",
        "state",
    )
    column_sortable_list = (
        "id",
        "name",
        "ip",
        "state",
        "creation_date",
    )
    column_filters = ("state", "owner", "machine_template")
    column_auto_select_related = True

    def _list_thumbnail(view, context, model, name):
        if not model.state == MachineState.READY:
            return ""

        return Markup(
            f'<a target="_blank" href="{model.make_access_url()}"><img style="max-height: 50px;" src="{model.make_url()}/screenshots/screenshot-thumb.png"></a>'
        )

    column_formatters = {
        "owner": _color_formatter,
        "state": _color_formatter,
        "machine_template": _color_formatter,
        "screenshot": _list_thumbnail,
    }

    @action(
        "stop_machine",
        "Stop Machine",
        "Are you sure you want to stop the selected machines?",
    )
    def action_stop_machine(self, ids):
        for id in ids:
            try:
                stop_machine2(id)
            except Exception as e:
                logging.warning("Error stopping machine: {str(e)}")
                flash(f"Failed to stop machine with id {id}", "danger")


class ProblemReport(db.Model):
    """
    Represents a user's problem report. It always has a user and
    may also be associated with a machine or data transfer job.

    The reports are meant to be shown to admins on the admin page
    """

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    creation_date = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    is_hidden = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User", back_populates="problem_reports")
    machine_id = db.Column(db.Integer, db.ForeignKey("machine.id"))
    machine = db.relationship("Machine", back_populates="problem_reports")
    data_transfer_job_id = db.Column(db.Integer, db.ForeignKey("data_transfer_job.id"))
    data_transfer_job = db.relationship(
        "DataTransferJob", back_populates="problem_reports"
    )


class ProtectedProblemReportModelView(ProtectedModelView):
    column_list = (
        "title",
        "description",
        "creation_date",
        "is_hidden",
        "user",
        "machine",
        "data_transfer_job",
    )
    column_searchable_list = ("title", "description")
    column_filters = ("is_hidden", "user", "machine", "data_transfer_job")
    column_auto_select_related = True
    form_columns = (
        "title",
        "description",
        "is_hidden",
        "user",
        "machine",
        "data_transfer_job",
    )


# log some stuff like logins and machine operations
class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    remote_ip = db.Column(db.String(16))
    sesh_id = db.Column(db.String(2))
    action = db.Column(db.String(128))
    state = db.Column(db.String(128))
    creation_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    finished_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    user = db.relationship("User")
    machine_id = db.Column(db.Integer, db.ForeignKey("machine.id"), index=True)
    machine = db.relationship("Machine")
    data_transfer_job_id = db.Column(db.Integer, db.ForeignKey("data_transfer_job.id"))
    data_transfer_job = db.relationship("DataTransferJob")

    def __repr__(self):
        return f"<////{self.id}//// {self.action} -> {self.state}>"


def create_audit(action, state=None, user=None, machine=None, data_transfer_job=None):
    # to be called at the beginning of the function or block that
    # is to be audited
    audit = Audit(
        user=user,
        sesh_id=user.sesh_id if user and user.is_authenticated else None,
        action=action,
        state=state if state else "running",
        remote_ip=get_remote_address() if has_request_context() else None,
        machine=machine,
        data_transfer_job=data_transfer_job,
    )
    db.session.add(audit)
    db.session.commit()
    logging.info(f"Created audit: {audit}")
    return audit


def get_audit(audit_id):
    audit = Audit.query.filter_by(id=audit_id).first()
    if not audit:
        logging.error(f"audit {audit_id} not found")
    return audit


def update_audit(
    audit, state="running", user=None, machine=None, data_transfer_job=None
):
    audit.state = state
    if machine:
        audit.machine = machine
    if user and user.is_authenticated:
        audit.user = user
        audit.sesh_id = user.sesh_id
    if data_transfer_job:
        audit.data_transfer_job = data_transfer_job
    db.session.commit()
    logging.info(f"Updated audit: {audit}")


# the last audit update, sets the .finished_date
def finish_audit(audit, state, user=None, machine=None, data_transfer_job=None):
    audit.state = state
    if machine:
        audit.machine = machine
    if user and user.is_authenticated:
        audit.user = user
        audit.sesh_id = user.sesh_id
    if data_transfer_job:
        audit.data_transfer_job = data_transfer_job
    audit.finished_date = datetime.datetime.utcnow()
    db.session.commit()
    logging.info(f"Finished audit: {audit}")


class ProtectedAuditModelView(ProtectedModelView):
    column_list = (
        "sesh_id",
        "user",
        "remote_ip",
        "action",
        "state",
        "machine",
        "data_transfer_job",
        "creation_date",
    )
    column_searchable_list = ("action", "state")
    column_filters = (
        "sesh_id",
        "user",
        "remote_ip",
        "action",
        "state",
        "machine",
        "data_transfer_job",
        "creation_date",
    )
    column_auto_select_related = True
    form_columns = (
        "user",
        "action",
        "state",
        "machine",
        "remote_ip",
        "data_transfer_job",
        "creation_date",
        "finished_date",
    )
    column_formatters = {
        "sesh_id": _color_formatter,
        "user": _color_formatter,
        "state": _color_formatter,
        "remote_ip": _color_formatter,
        "action": _color_formatter,
        "state": _color_formatter,
        "machine": _color_formatter,
        "data_transfer_job": _color_formatter,
    }


# add flask-sqlalchemy views to flask-admin
admin.add_view(ProtectedUserModelView(User, db.session))
admin.add_view(ProtectedDataSourceModelView(DataSource, db.session))
admin.add_view(ProtectedDataTransferJobModelView(DataTransferJob, db.session))
admin.add_view(ProtectedGroupModelView(Group, db.session))
admin.add_view(ProtectedGroupWelcomePageModelView(GroupWelcomePage, db.session))
admin.add_view(ProtectedMachineProviderModelView(MachineProvider, db.session))
admin.add_view(ProtectedSoftwareModelView(Software, db.session))
admin.add_view(ProtectedImageModelView(Image, db.session))
admin.add_view(ProtectedMachineTemplateModelView(MachineTemplate, db.session))
admin.add_view(ProtectedMachineModelView(Machine, db.session))
admin.add_view(ProtectedProblemReportModelView(ProblemReport, db.session))
admin.add_view(ProtectedAuditModelView(Audit, db.session))
admin.add_view(
    ProtectedAddUserToGroupView(name="Add Users to Group", endpoint="addusertogroup")
)
admin.add_view(
    ProtectedEnableAndAddUserToGroupView(
        name="Enable Users and add to Group", endpoint="enableandaddusertogroup"
    )
)
admin.add_view(
    ProtectedAssignDataSourcesView(
        name="Assign Data Sources", endpoint="assigndatasources"
    )
)
admin.add_view(ProtectedSetupUserView(name="Setup User", endpoint="setupuser"))


# This is used in base.jinja2 to build the side bar menu
def get_main_menu():
    return [
        {
            "icon": "house",
            "name": gettext("Welcome page"),
            "href": "/",
        },
        {
            "icon": "cubes",
            "name": gettext("Machines"),
            "href": "/machines",
        },
        {
            "icon": "database",
            "name": gettext("Data"),
            "href": "/data",
        },
        {
            "icon": "gear",
            "name": gettext("Settings"),
            "href": "/settings",
        },
        {
            "icon": "users-gear",
            "name": gettext("Group"),
            "href": "/group_mgmt",
            "admin_only": True,
            "group_admin_only": True,
        },
        {
            "icon": "lightbulb",
            "name": gettext("Help"),
            "href": "/help",
        },
        {
            "icon": "book",
            "name": gettext("Citations"),
            "href": "/citations",
        },
        {
            "icon": "circle-question",
            "name": gettext("About"),
            "href": "/about",
        },
        {
            "icon": "toolbox",
            "name": gettext("Admin"),
            "href": "/admin",
            "admin_only": True,
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
    t = gettext("Access denied")
    m = gettext("Sorry, you don't have access to that page or resource.")

    return render_template("error.jinja2", message=m, title=t, code=403), 403


# 404 error handler
@app.errorhandler(404)
def notfound_handler(e):
    t = gettext("Not found")
    m = gettext("Sorry, that page or resource could not be found.")

    return render_template("error.jinja2", message=m, title=t, code=404), 404


# 429 error handler
@app.errorhandler(429)
def toomanyrequests_handler(e):
    t = gettext("Too many requests")
    m = gettext(
        "Sorry, you're making too many requests. Please wait a while and then try again."
    )

    return render_template("error.jinja2", message=m, title=t, code=429), 429


# 500 error handler
@app.errorhandler(500)
def applicationerror_handler(e):
    t = gettext("Application error")
    m = gettext("Sorry, the application encountered a problem.")

    return render_template("error.jinja2", message=m, title=t, code=500), 500


class SwitchGroupForm(FlaskForm):
    switch_group = SelectField("Group", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Submit")


def profile_complete_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.group:
            return redirect(url_for("pick_group"))
        if not current_user.is_enabled:
            return redirect(url_for("not_activated"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/switch_group", methods=["POST"])
@limiter.limit("60 per hour")
@login_required
@profile_complete_required
def switch_group():
    form = SwitchGroupForm()
    form.switch_group.choices = [(g.id, g.name) for g in Group.query.all()]

    if form.validate_on_submit():
        group_id = form.switch_group.data
        current_user.group_id = group_id
        db.session.commit()

    return redirect(url_for("welcome"))


@app.context_processor
def inject_globals():
    """Add some stuff into all templates."""

    switch_group_form = SwitchGroupForm()
    if current_user.is_authenticated:
        switch_group_form.switch_group.data = current_user.group_id
        if current_user.is_admin:
            # the admin can switch to any group
            switch_group_form.switch_group.choices = [
                (g.id, g.name) for g in Group.query.all()
            ]
        elif groups := current_user.extra_data.get("groups", []):
            switch_group_form.switch_group.choices = [
                (g.id, g.name)
                for g in db.session.query(Group)
                .filter(Group.id.in_([int(group["id"]) for group in groups]))
                .all()
            ]
        else:
            switch_group_form.switch_group.choices = []

    return {
        "icon": icon,
        "icon_regular": icon_regular,
        "email": email,
        "external_link": external_link,
        "info": info,
        "idea": idea,
        "main_menu": get_main_menu(),
        "humanize": humanize,
        "time_now": datetime.datetime.utcnow(),
        "version": version,
        "hostname": hostname,
        "LOGIN_RECAPTCHA": LOGIN_RECAPTCHA,
        "switch_group_form": switch_group_form,
        "Machine": Machine,
        "MachineState": MachineState,
        "MAIL_SENDER": MAIL_SENDER,
    }


# adds request logging to waitress
class RequestLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        start_time = time.time()

        def custom_start_response(status, response_headers, exc_info=None):
            end_time = time.time()
            duration = end_time - start_time
            request_log = f"waitress: {request.remote_addr} {duration:.4f}s {request.method} {status} {request.path}"
            logging.info(request_log)
            return start_response(status, response_headers, exc_info)

        return self.app(environ, custom_start_response)


app.wsgi_app = ProxyFix(
    RequestLoggingMiddleware(app.wsgi_app), x_for=1, x_proto=1, x_host=1
)


@login_manager.user_loader
def load_user(user_id):
    """
    This is called by flask-login on every request to load the user
    """
    return User.query.filter_by(id=int(user_id)).first()


# get the user's language or pick it based on browser flags
def get_locale():
    if current_user and current_user.is_authenticated:
        if current_user.language:
            return current_user.language
    lang = request.accept_languages.best_match(["en", "zh", "sl"])
    logging.info(f"language best match: {lang}")
    return lang


def get_timezone():
    if current_user and current_user.is_authenticated:
        return current_user.timezone


babel = Babel(app, locale_selector=get_locale, timezone_selector=get_timezone)


class LoginForm(FlaskForm):
    username = StringField(
        lazy_gettext("Username or email"),
        validators=[DataRequired(), Length(min=2, max=200)],
    )
    password = PasswordField(
        lazy_gettext("Password"), validators=[DataRequired(), Length(min=8, max=100)]
    )
    submit = SubmitField("Sign In")


oauth = OAuth(app)

if os.environ.get("GOOGLE_OAUTH2_CLIENT_ID"):
    logging.info("using google logins")
    google = oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_OAUTH2_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_OAUTH2_CLIENT_SECRET"),
        access_token_url="https://accounts.google.com/o/oauth2/token",
        access_token_params=None,
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        authorize_params=None,
        api_base_url="https://www.googleapis.com/oauth2/v1/",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
        client_kwargs={"scope": "email profile"},
    )

if os.environ.get("ADA2025_IRIS_IAM_OAUTH2_CLIENT_ID"):
    logging.info("using iris iam logins")
    iris_iam = oauth.register(
        name="iris_iam",
        client_id=os.environ.get("ADA2025_IRIS_IAM_OAUTH2_CLIENT_ID"),
        client_secret=os.environ.get("ADA2025_IRIS_IAM_OAUTH2_CLIENT_SECRET"),
        access_token_url="https://iris-iam.stfc.ac.uk/token",
        authorize_url="https://iris-iam.stfc.ac.uk/authorize",
        api_base_url="https://iris-iam.stfc.ac.uk/",
        server_metadata_url="https://iris-iam.stfc.ac.uk/.well-known/openid-configuration",
        client_kwargs={"scope": "email profile openid"},
    )


@app.route("/error_test")
@limiter.limit("60 per hour")
@login_required
def error_test():
    # unhandled error, used for eg: testing sentry.io integration
    if current_user.is_admin:
        raise RuntimeError("This is a test error")
    else:
        abort(404)


@app.route("/google_login")
@limiter.limit("60 per hour")
def google_login():
    # send the users to google to log in. once they're logged
    # in, they're sent back to google_authorize, where we
    # make an account for them from the data that google
    # provided
    audit = create_audit("google login")
    google = oauth.create_client("google")
    redirect_uri = url_for("google_authorize", _external=True)
    finish_audit(audit, state="ok")
    return google.authorize_redirect(redirect_uri)


@app.route("/iris_iam_login")
@limiter.limit("60 per hour")
def iris_iam_login():
    # send the users to google to log in. once they're logged
    # in, they're sent back to google_authorize, where we
    # make an account for them from the data that google
    # provided
    audit = create_audit("iris login")
    iris_iam = oauth.create_client("iris_iam")
    redirect_uri = url_for("iris_iam_authorize", _external=True)
    finish_audit(audit, state="ok")
    return iris_iam.authorize_redirect(redirect_uri)


def gen_unique_username(email, max_attempts=1000):
    # try really hard to generate a unique username from an email
    username = ""
    attempt = 0
    try:
        email_prefix = email.split("@")[0]
    except:
        email_prefix = ""
    # emails can have lots of characters, but we only want [a-Z,0-9,.]
    email_prefix = "".join([ch for ch in email_prefix if ch.isalnum() or ch == "."])

    while True:
        if not email_prefix:
            username = gen_token(16)
        elif not username:
            username = email_prefix
        else:
            username = email_prefix + "." + gen_token(4)

        if not User.query.filter_by(username=username).first():
            return username

        if attempt > max_attempts // 2:
            username = gen_token(24)
        if attempt > max_attempts:
            abort(500)

        attempt = attempt + 1


@app.route("/not_activated")
@login_required
@limiter.limit("60 per minute")
def not_activated():
    if not current_user.group:
        return redirect(url_for("pick_group"))
    if not current_user.is_enabled:
        return render_template("not_activated.jinja2", title=gettext("Not activated"))
    else:
        return redirect("/welcome")


class PickGroupForm(FlaskForm):
    group = SelectField(
        lazy_gettext("Please pick the group you want to join:"),
        validators=[DataRequired()],
    )
    submit = SubmitField(lazy_gettext("Continue"))


@app.route("/pick_group", methods=["GET", "POST"])
@limiter.limit("60 per minute")
@login_required
def pick_group():
    if current_user.group:
        return redirect(url_for("welcome"))

    form = PickGroupForm()
    public_groups = (
        db.session.query(Group).filter(Group.is_public).order_by(desc(Group.id)).all()
    )
    form.group.choices = [(g.id, g.name) for g in public_groups]

    if request.method == "POST":
        if form.validate_on_submit():
            group = Group.query.filter_by(id=form.group.data).first_or_404()
            current_user.group = group
            db.session.commit()

            def inform_group_admins(group_id, site_root):
                if not MAIL_SENDER:
                    logging.info("inform_group_admins: Mail sender not defined")
                    return
                with app.app_context():
                    group_admins = (
                        db.session.query(User)
                        .filter(
                            and_(
                                User.group_id == group_id,
                                User.is_group_admin,
                                User.is_enabled,
                            )
                        )
                        .all()
                    )
                    if not group_admins:
                        logging.error(f"No group admins for group id: {group_id}")
                        return
                    emails_to = [ga.email for ga in group_admins]
                    logging.info(
                        f"Sending email about new user to group admins: {emails_to}"
                    )
                    msg = Message(
                        "New user in Ada group", sender=MAIL_SENDER, bcc=emails_to
                    )
                    msg.body = f"""Hi,

A new user has picked your group on Ada Data Analysis.

The user won't be able to do anything until a group admin approves them.

If you want to do that you need to go to Group Management on the site:

{site_root}group_mgmt

and click the green enable user account button.

You're receiving this email because you're a group admin on {site_root}.
"""
                    mail.send(msg)

            site_root = request.url_root
            threading.Thread(
                target=inform_group_admins, args=(group.id, site_root)
            ).start()
            return redirect(url_for("welcome"))
        else:
            flash("There was an error picking the group. Please try again.")
            return redirect(url_for("pick_group"))

    return render_template(
        "pick_group.jinja2",
        form=form,
        title=gettext("Setup"),
    )


@app.route("/google_authorize")
@limiter.limit("60 per hour")
def google_authorize():
    # google has authenticated the user and sent them back
    # here, make an account if they don't have one and log
    # them in
    audit = create_audit("google auth")
    try:
        google = oauth.create_client("google")
        google.authorize_access_token()
        resp = google.get("userinfo")
        if resp.status_code != 200:
            update_audit(audit, state="bad userinfo")
            raise Exception("Failed to get user info")
        user_info = resp.json()

        user = User.query.filter_by(email=user_info.get("email")).first()

        # Update or create the user
        if user:
            update_audit(audit, "existing user", user=user)
            # Update user info if needed
            user.given_name = user_info.get("given_name", user.given_name)
            user.family_name = user_info.get("family_name", user.family_name)
            user.provider = "google"
            user.provider_id = user_info.get("id", user.provider_id)
        else:
            # Create a new user
            update_audit(audit, "new user 1")
            user = User(
                username=gen_unique_username(user_info.get("email", "")),
                given_name=user_info.get("given_name", ""),
                family_name=user_info.get("family_name", ""),
                email=user_info.get("email", ""),
                provider="google",
                provider_id=user_info.get("id", ""),
                language="en",  # TODO: google gives locale, handle it here
                timezone="Europe/London",
            )
            db.session.add(user)
            update_audit(audit, "new user 2", user=user)

        db.session.commit()

        # log the user in
        user.sesh_id = gen_token(2)
        login_user(user)
        finish_audit(audit, "ok")

        return determine_redirect(session.get("share_accept_token"))

    except Exception as e:
        finish_audit(audit, "error")
        # Log the error and show an error message
        app.logger.error(e)
        flash(
            gettext(
                "An error occurred while processing your Google login. Please try again."
            ),
            "danger",
        )
        return redirect(url_for("login"))


@app.route("/iris_iam_authorize")
@limiter.limit("60 per hour")
def iris_iam_authorize():
    # iris iam has authenticated the user and sent them back
    # here, make an account if they don't have one and log
    # them in
    audit = create_audit("iris iam auth")
    try:
        iris_iam = oauth.create_client("iris_iam")
        iris_iam.authorize_access_token()
        resp = iris_iam.get("userinfo")
        if resp.status_code != 200:
            update_audit(audit, state="bad userinfo")
            logging.info(resp.status_code)
            logging.info(resp.text)
            raise Exception("Failed to get user info")
        user_info = resp.json()

        user = User.query.filter_by(email=user_info.get("email")).first()

        # Update or create the user
        if user:
            update_audit(audit, "existing user", user=user)
            # Update user info if needed
            user.given_name = user_info.get("given_name", user.given_name)
            user.family_name = user_info.get("family_name", user.family_name)
            user.provider = "iris_iam"
            user.provider_id = user_info.get("id", user.provider_id)
        else:
            # Create a new user
            update_audit(audit, "new user 1")
            user = User(
                username=gen_unique_username(user_info.get("email", "")),
                given_name=user_info.get("given_name", ""),
                family_name=user_info.get("family_name", ""),
                email=user_info.get("email", ""),
                provider="iris_iam",
                provider_id=user_info.get("id", ""),
                language="en",
                timezone="Europe/London",
            )
            db.session.add(user)
            update_audit(audit, "new user 2", user=user)

        db.session.commit()

        # log the user in
        user.sesh_id = gen_token(2)
        login_user(user)
        finish_audit(audit, "ok")

        return determine_redirect(session.get("share_accept_token"))

    except Exception as e:
        finish_audit(audit, "error")
        # Log the error and show an error message
        app.logger.error(e)
        flash(
            gettext(
                "An error occurred while processing your IRIS login. Please try again."
            ),
            "danger",
        )
        return redirect(url_for("login"))


@app.route("/impersonate/<user_id>")
@limiter.limit("60 per hour")
@login_required
@profile_complete_required
def impersonate_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user_to_impersonate = User.query.filter_by(id=user_id).first_or_404()

    login_user(user_to_impersonate)
    flash("Impersonating user", "danger")
    return redirect(url_for("welcome"))


@app.route("/visit_machine/<m_id>")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def visit_machine(m_id):
    # redirect the user to the machine
    audit = create_audit("visit machine", user=current_user)
    m = Machine.query.filter_by(id=m_id).first()
    if not m:
        finish_audit(audit, "bad machine id")
        flash("Machine not found", "danger")
        return redirect(url_for("machines"))

    update_audit(audit, machine=m)

    if current_user != m.owner and current_user not in m.shared_users:
        finish_audit(audit, "bad user")
        flash("Machine not found", "danger")
        return redirect(url_for("machines"))

    # Uxse per machine access key
    access_token = m.access_token

    if m.hostname and m.machine_template.extra_data.get("has_https"):
        machine_url = "https://" + m.hostname + "/" + access_token
    else:
        machine_url = "http://" + m.ip + "/" + access_token

    finish_audit(audit, "ok")
    return redirect(machine_url)


class UserInfoForm(FlaskForm):
    given_name = StringField(
        lazy_gettext("Given Name"), validators=[DataRequired(), Length(max=100)]
    )
    family_name = StringField(
        lazy_gettext("Family Name"), validators=[DataRequired(), Length(max=100)]
    )
    organization = StringField(
        lazy_gettext("Organization"), validators=[Length(max=200)]
    )
    job_title = StringField(lazy_gettext("Job Title"), validators=[Length(max=200)])
    email = StringField(
        lazy_gettext("Email"), validators=[DataRequired(), Email(), Length(max=200)]
    )
    language = SelectField(
        lazy_gettext("Language"),
        validators=[DataRequired()],
        choices=[
            (code, Locale.parse(code).get_display_name()) for code in ["en", "zh", "sl"]
        ],
    )
    timezone = SelectField(
        lazy_gettext("Timezone"),
        validators=[DataRequired()],
        choices=pytz.all_timezones,
    )
    password = PasswordField(lazy_gettext("New Password"), validators=[Length(max=200)])
    password_confirm = PasswordField(
        lazy_gettext("Confirm New Password"),
        validators=[
            Length(max=200),
            EqualTo("password", message=lazy_gettext("Passwords must match.")),
        ],
    )

    submit = SubmitField(lazy_gettext("Update"))


@app.route("/settings", methods=["GET", "POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def settings():
    form = UserInfoForm()

    if request.method == "POST":
        if form.validate_on_submit():
            error_msg = ""
            if form.language.data not in [x[0] for x in form.language.choices]:
                error_msg = gettext("Bad language specified")
            if form.timezone.data not in form.timezone.choices:
                error_msg = gettext("Bad timezone specified")
            if not is_name_safe(form.given_name.data):
                error_msg = gettext("Sorry, that given name is not allowed.")
            if not is_name_safe(form.family_name.data):
                error_msg = gettext("Sorry, that last name is not allowed.")
            if not is_name_safe(form.email.data):
                error_msg = gettext("Sorry, that email is not allowed.")
            if u := User.query.filter_by(email=form.email.data).first():
                if u != current_user:
                    error_msg = gettext(
                        "Sorry, that email can't be used. Please choose another or contact us for support."
                    )
            if form.password.data:
                if form.password.data != form.password_confirm.data:
                    error_msg = gettext("The passwords you entered don't match.")
                if len(form.password.data) < 8:
                    error_msg = gettext("New password has to be at least 8 characters.")

            logging.warning(f"user settings change failed: {error_msg}")
            if error_msg:
                flash(error_msg, "danger")
                return redirect(url_for("settings"))

            current_user.given_name = form.given_name.data
            current_user.family_name = form.family_name.data
            current_user.organization = form.organization.data
            current_user.job_title = form.job_title.data
            current_user.email = form.email.data
            current_user.language = form.language.data
            current_user.timezone = form.timezone.data
            if form.password.data:
                current_user.set_password(form.password.data)

            db.session.commit()

            flash(gettext("Your changes have been saved."))
            return redirect(url_for("settings"))
        else:
            error_msg = ""
            for field, errors in form.errors.items():
                for error in errors:
                    error_msg += f"{field}: {error}<br/>"

            flash(f"Sorry, the form could not be validated:<br/> {error_msg}", "danger")
            return redirect(url_for("settings"))

    elif request.method == "GET":
        form.given_name.data = current_user.given_name
        form.family_name.data = current_user.family_name
        form.organization.data = current_user.organization
        form.job_title.data = current_user.job_title
        form.email.data = current_user.email
        form.language.data = current_user.language
        form.timezone.data = current_user.timezone

    return render_template(
        "settings.jinja2",
        title=gettext("Settings"),
        form=form,
    )


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("60 per hour")
def login():
    """
    Login page and login logic
    """

    # show the google login button or not
    show_google_button = False
    show_iris_iam_button = False
    if os.environ.get("GOOGLE_OAUTH2_CLIENT_ID"):
        show_google_button = True
    if os.environ.get("ADA2025_IRIS_IAM_OAUTH2_CLIENT_ID"):
        show_iris_iam_button = True

    form = LoginForm()

    # log out users who go to the login page
    if current_user.is_authenticated:
        audit = create_audit("logout", user=current_user)
        logout_user()
        finish_audit(audit, state="ok")
        flash(gettext("You've been logged out."))
        return render_template(
            "login.jinja2",
            title=gettext("Login"),
            form=form,
            show_google_button=show_google_button,
            show_iris_iam_button=show_iris_iam_button,
            show_stfc_logo=True,
        )

    # POST path
    if request.method == "POST":
        audit = create_audit("login")
        if LOGIN_RECAPTCHA:
            if not recaptcha.verify():
                finish_audit(audit, "recaptcha failed")
                flash(gettext("Could not verify captcha. Try again."), "danger")
                return render_template(
                    "login.jinja2",
                    title=gettext("Login"),
                    form=form,
                    show_google_button=show_google_button,
                    show_iris_iam_button=show_iris_iam_button,
                    show_stfc_logo=True,
                )
        if form.validate_on_submit():
            user = (
                db.session.query(User)
                .filter(
                    or_(
                        User.username == form.username.data,
                        User.email == form.username.data,
                    )
                )
                .first()
            )
            # oauth2 returning users
            if user and user.provider_id:
                if user.provider == "google":
                    # google users
                    finish_audit(audit, "google login")
                    return redirect(url_for("google_login"))
                elif user.provider == "iris_iam":
                    # iris iam users
                    finish_audit(audit, "iris iam login")
                    return redirect(url_for("iris_iam_login"))
                else:
                    finish_audit(audit, "invalid provider")
                    flash(gettext("Invalid provider"), "danger")
                    return render_template(
                        "login.jinja2",
                        title=gettext("Login"),
                        form=form,
                        show_google_button=show_google_button,
                        show_iris_iam_button=show_iris_iam_button,
                        show_stfc_logo=True,
                    )

            # oauth2 users trying to log in locally but don't have a password
            if user and user.provider != "local" and not user.password_hash:
                finish_audit(audit, "local login no pw")
                flash(
                    gettext(
                        "Sorry, you can't use a local login. Try using the login method you signed in (eg. Google) with the first time, or contact support for help.",
                    ),
                    "danger",
                )
                return render_template(
                    "login.jinja2",
                    title=gettext("Login"),
                    form=form,
                    show_google_button=show_google_button,
                    show_iris_iam_button=show_iris_iam_button,
                    show_stfc_logo=True,
                )

            # local users or oauth2 users who have set a password
            if user and user.check_password(form.password.data):
                # log user in
                user.sesh_id = gen_token(2)
                login_user(user)
                resp = determine_redirect(session.get("share_accept_token"))
                finish_audit(audit, "ok", user=user)
                return resp
            else:
                finish_audit(audit, "bad password")
                flash(gettext("Invalid username or password."), "danger")
        else:
            finish_audit(audit, "bad form")
            logging.warning(f"wtforms didn't validate form: { form.errors }")
            # technically it's not invalid but don't give that away
            flash(gettext("Invalid username or password."), "danger")

    # GET path
    next_url = request.args.get("next")
    if is_next_uri_share_accept(next_url):
        res = re.search(r"[A-Za-z0-9]{16}$", next_url)
        session["share_accept_token"] = res.group(0)

    return render_template(
        "login.jinja2",
        title=gettext("Login"),
        form=form,
        show_google_button=show_google_button,
        show_iris_iam_button=show_iris_iam_button,
        show_stfc_logo=True,
    )


class ForgotPasswordForm(FlaskForm):
    username = StringField(
        lazy_gettext(
            "Username or email of account that you have forgotten the password to"
        ),
        validators=[DataRequired(), Length(min=2, max=200)],
    )
    submit = SubmitField("Forgot Password")


@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit(lambda: {"GET": "60 per hour", "POST": "5 per hour"}[request.method])
def forgot_password():
    if not MAIL_SENDER:
        abort(404)

    form = ForgotPasswordForm()

    if request.method == "POST":
        audit = create_audit("forgot password")

        if LOGIN_RECAPTCHA:
            if not recaptcha.verify():
                finish_audit(audit, "recaptcha failed")
                flash(gettext("Could not verify captcha. Try again."), "danger")
                return render_template(
                    "forgot_password.jinja2",
                    title=gettext("Forgot password"),
                    form=form,
                )

        if form.validate_on_submit():
            user = (
                db.session.query(User)
                .filter(
                    or_(
                        User.username == form.username.data,
                        User.email == form.username.data,
                    )
                )
                .first()
            )

            flash(
                gettext(
                    "An email has been sent to the account associated with the given username or email address (if it exists)"
                )
            )

            if not user:
                logging.info("Account doesn't exist")
                finish_audit(audit, "no account")
                return redirect(url_for("forgot_password"))

            site_root = request.url_root
            s = URLSafeTimedSerializer(ADA2025_EMAIL_LOGIN_SECRET_KEY)
            data_to_encode = [
                str(user.id),
                request.remote_addr,
            ]
            encoded_data = s.dumps(data_to_encode)
            login_link = (
                site_root + url_for("email_login", login_token=encoded_data)[1:]
            )
            threading.Thread(
                target=email_forgot_password_link,
                args=(site_root, login_link, user.id),
            ).start()

            finish_audit(audit, "ok")

            return redirect(url_for("forgot_password"))

    # GET path
    return render_template(
        "forgot_password.jinja2",
        title=gettext("Forgot password"),
        form=form,
    )


@app.route("/email_login/<login_token>")
@limiter.limit("60 per hour")
def email_login(login_token):
    audit = create_audit("email login")

    if current_user.is_authenticated:
        finish_audit(audit, "already logged in", user=current_user)
        return redirect(url_for("login"))

    s = URLSafeTimedSerializer(ADA2025_EMAIL_LOGIN_SECRET_KEY)
    try:
        if login_token in used_email_login_tokens:
            raise Exception("Token used up")
        user_id, original_ip = s.loads(login_token, max_age=1800)  # in seconds
    except Exception as e:
        logging.warning(f"token exception: {e}")
        flash(
            gettext(
                'That link is invalid or expired. Please login below or request another login link on the "Forgot Password" page.'
            ),
            "danger",
        )

        finish_audit(audit, "invalid token")
        return redirect(url_for("login"))

    if original_ip != request.remote_addr:
        flash(
            gettext(
                'Please use the email login link from the same device (IP address) that you requested it from, or request a new one on the "Forgot Password" page.'
            ),
            "danger",
        )
        finish_audit(audit, "wrong ip")
        return redirect(url_for("login"))

    user = User.query.filter_by(id=user_id).first()

    if not user:
        flash("User doesn't exist.", "danger")
        logging.info(f"User {user_id} doesn't exist")
        finish_audit(audit, "not user")
        return redirect(url_for("login"))

    login_user(user)
    logging.info(f"Logged user {current_user.id} in using email login")
    used_email_login_tokens.append(login_token)
    flash("You have been logged in successfully. You can set a new password below.")
    finish_audit(audit, "ok", user=current_user)
    return redirect(url_for("settings"))


class RegistrationForm(FlaskForm):
    username_min = 2
    username_max = 32
    username = StringField(
        lazy_gettext("Username"),
        validators=[
            DataRequired(),
            Length(min=username_min, max=username_max),
            Regexp(
                r"^[A-Za-z0-9\.]*$",
                message=gettext(
                    "Sorry, username can only contain letters, numbers, and dots."
                ),
            ),
        ],
    )
    password_min = 8
    password_max = 100
    password = PasswordField(
        lazy_gettext("Password"),
        validators=[DataRequired(), Length(min=password_min, max=password_max)],
    )
    confirm_password = PasswordField(
        lazy_gettext("Confirm Password"),
        validators=[
            DataRequired(),
            Length(min=password_min, max=password_max),
            EqualTo("password", message=lazy_gettext("Passwords must match.")),
        ],
    )
    given_name_min = 2
    given_name_max = 100
    given_name = StringField(
        lazy_gettext("Given Name"),
        validators=[DataRequired(), Length(min=given_name_min, max=given_name_max)],
    )
    family_name_min = 2
    family_name_max = 100
    family_name = StringField(
        lazy_gettext("Family Name"),
        validators=[DataRequired(), Length(min=family_name_min, max=family_name_max)],
    )
    language = SelectField(
        lazy_gettext("Language"),
        validators=[DataRequired()],
        choices=[
            (code, Locale.parse(code).get_display_name()) for code in ["en", "zh", "sl"]
        ],
    )
    timezone = SelectField(
        lazy_gettext("Timezone"),
        validators=[DataRequired()],
        choices=pytz.all_timezones,
    )
    email_min = 4
    email_max = 200
    email = StringField(
        lazy_gettext("Email"),
        validators=[DataRequired(), Email(), Length(min=email_min, max=email_max)],
    )
    organization_min = 2
    organization_max = 200
    organization = StringField(
        lazy_gettext("Organization"),
        validators=[DataRequired(), Length(min=organization_min, max=organization_max)],
    )
    job_title_min = 2
    job_title_max = 200
    job_title = StringField(
        lazy_gettext("Job Title"),
        validators=[DataRequired(), Length(min=job_title_min, max=job_title_max)],
    )
    submit = SubmitField(lazy_gettext("Register"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("60 per hour")
def register():
    # log out users who go to the register page
    if current_user.is_authenticated:
        return redirect(url_for("login"))

    # register a user account
    form = RegistrationForm()

    if request.method == "POST":
        audit = create_audit("registration")
        if not recaptcha.verify():
            finish_audit(audit, "recaptcha failed")
            flash("Could not verify captcha. Try again.", "danger")
            return render_template(
                "register.jinja2",
                form=form,
                title=gettext("Register account"),
            )

        if form.validate_on_submit():
            error_msg = ""
            if form.language.data not in [l[0] for l in form.language.choices]:
                error_msg = gettext("Bad language specified")
            if form.timezone.data not in form.timezone.choices:
                error_msg = gettext("Bad timezone specified")
            if not is_name_safe(form.given_name.data):
                error_msg = "Sorry, that given name is not allowed."
            if not is_name_safe(form.family_name.data):
                error_msg = "Sorry, that last name is not allowed."
            if not is_name_safe(form.username.data):
                error_msg = "Sorry, that username name is not allowed."
            if not is_name_safe(form.email.data):
                error_msg = "Sorry, that email is not allowed."
            if User.query.filter_by(username=form.username.data).first():
                error_msg = gettext(
                    "Sorry, that username or email is taken. Please choose another."
                )
            if User.query.filter_by(email=form.email.data).first():
                error_msg = gettext(
                    "Sorry, that username or email is taken. Please choose another."
                )
            if error_msg:
                finish_audit(audit, "validation failed")
                logging.info(f"Registration error: {error_msg}")
                flash(error_msg, "danger")
                return render_template(
                    "register.jinja2",
                    form=form,
                    title=gettext("Register account"),
                )

            new_user = User(
                username=form.username.data,
                given_name=form.given_name.data,
                family_name=form.family_name.data,
                email=form.email.data,
                provider="local",
                provider_id="",
                language=form.language.data,
                timezone=form.timezone.data,
                organization=form.organization.data,
                job_title=form.job_title.data,
            )
            new_user.set_password(form.password.data)

            # Give new users admin's data sources TODO: remove this
            new_user.data_sources = User.query.filter_by(id=1).first().data_sources

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            finish_audit(audit, "ok", user=new_user)

            return redirect(url_for("welcome"))
        else:
            error_msg = ""
            for field, errors in form.errors.items():
                field = field.replace("_", " ").title()
                for error in errors:
                    error_msg += f"{field}: {error}<br/>"

            flash(f"Sorry, the form could not be validated:<br/> {error_msg}", "danger")
            return render_template(
                "register.jinja2",
                form=form,
                title=gettext("Register account"),
            )

    return render_template(
        "register.jinja2",
        form=form,
        title=gettext("Register account"),
    )


@app.route("/")
@limiter.limit("60 per minute")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("welcome"))
    else:
        return render_template("landing.jinja2", title=gettext("Ada Data Analysis"))


class EditWelcomePageForm(FlaskForm):
    content = TextAreaField(
        "Content",
        render_kw={"rows": 20},
    )
    submit = SubmitField("Update Welcome Page")


@app.route("/group_mgmt", methods=["GET", "POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def group_mgmt():
    if not current_user.is_admin and not current_user.is_group_admin:
        flash("Invalid page", "danger")
        return redirect(url_for("welcome"))

    form = EditWelcomePageForm()

    if request.method == "POST":
        if form.validate_on_submit():
            group = current_user.group
            if group.welcome_page:
                group.welcome_page.content = form.content.data
                group.welcome_page.updated_date = datetime.datetime.utcnow()
            else:
                new_welcome_page = GroupWelcomePage(
                    content=form.content.data,
                    group_id=group.id,
                )
                db.session.add(new_welcome_page)
            db.session.commit()

            flash("Welcome message updated")
            return redirect(url_for("group_mgmt"))

    group_users = (
        db.session.query(User)
        .filter(
            and_(
                User.group == current_user.group,
                ~User.is_admin,  # group admins can't control other admins
                ~User.is_group_admin,
                User.id != current_user.id,
            )
        )
        .order_by(asc(User.is_enabled), desc(User.creation_date))
        .all()
    )

    if current_user.group.welcome_page:
        form.content.data = current_user.group.welcome_page.content

    return render_template(
        "group_mgmt.jinja2",
        group_users=group_users,
        form=form,
        title=gettext("Group"),
    )


@app.route("/enable_user", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def enable_user():
    user_id = request.json.get("user_id")

    if not user_id:
        abort(404)

    user = User.query.filter_by(id=user_id).first_or_404()

    perm_ok = current_user.is_admin or (
        current_user.is_group_admin
        and user.group == current_user.group
        and not (user.is_admin or user.is_group_admin)
    )
    if not perm_ok:
        abort(403)

    user.is_enabled = not user.is_enabled
    db.session.commit()

    def inform_enabled_user(user_id, site_root):
        if not MAIL_SENDER:
            logging.info("inform_group_admins: Mail sender not defined")
            return
        with app.app_context():
            user = User.query.filter_by(id=user_id).first()
            if not user:
                logging.error(f"No user for id: {user_id}")
                return
            email_to = user.email
            logging.info(f"Sending email enabled account to: {email_to}")
            msg = Message(
                "Ada Data Analysis account activated",
                sender=MAIL_SENDER,
                recipients=[email_to],
            )
            msg.body = f"""Hi,

Your account on Ada Data Analysis has been activated.

You can now use the site by clicking:

{site_root}

You're receiving this email because you've registered on {site_root}.
"""
            mail.send(msg)

    site_root = request.url_root
    threading.Thread(target=inform_enabled_user, args=(user.id, site_root)).start()

    return "OK"


@app.route("/disable_user", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def disable_user():
    # disable user
    user_id = request.json.get("user_id")

    if not user_id:
        abort(404)

    user = User.query.filter_by(id=user_id).first_or_404()

    perm_ok = current_user.is_admin or (
        current_user.is_group_admin
        and user.group == current_user.group
        and not (user.is_admin or user.is_group_admin)
    )
    if not perm_ok:
        abort(403)

    user.is_enabled = not user.is_enabled
    db.session.commit()

    return "OK"


@app.route("/remove_user", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def remove_user():
    # disable user and remove from group
    user_id = request.json.get("user_id")

    if not user_id:
        abort(404)

    user = User.query.filter_by(id=user_id).first_or_404()

    perm_ok = current_user.is_admin or (
        current_user.is_group_admin
        and user.group == current_user.group
        and not (user.is_admin or user.is_group_admin)
    )
    if not perm_ok:
        abort(403)

    user.group = None
    user.is_enabled = False
    db.session.commit()

    return "OK"


class MultiCheckboxField(QuerySelectMultipleField):
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()


class SetupUser2(FlaskForm):
    data_sources = MultiCheckboxField("Data Sources", get_label="name")
    submit = SubmitField("Setup User")


@app.route("/setup_user/<user_id>", methods=["GET", "POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def setup_user(user_id):
    # assign data sources to users. This version is for group admins.
    user = User.query.filter_by(id=user_id).first_or_404()

    if not (current_user.is_group_admin or current_user.is_admin):
        flash("Invalid page", "danger")
        return redirect(url_for("welcome"))

    # Check group access right
    if user.group != current_user.group:
        flash("Invalid user selected", "danger")
        return redirect(url_for("welcome"))

    form = SetupUser2()
    form.data_sources.query_factory = (
        lambda: db.session.query(DataSource)
        .filter(
            DataSource.id.in_(
                [ds.id for ds in current_user.data_sources + user.data_sources]
            )
        )
        .order_by(desc(DataSource.id))
        .all()
    )

    if request.method == "POST":
        if form.validate_on_submit():
            # get allowed data sources by calling the query factory
            allowed_data_sources = form.data_sources.query_factory()

            # check that all submitted data sources are in the allowed data sources
            for data_source in form.data_sources.data:
                if data_source not in allowed_data_sources:
                    flash("Invalid data source selected.", "danger")
                    return redirect(url_for("welcome"))

            user.data_sources = form.data_sources.data
            db.session.commit()
            flash("Data sources for user have been updated.")
            return redirect(url_for("group_mgmt"))
        else:
            flash("Couldn't validate form")
            return redirect(url_for("welcome"))

    # GET
    form.data_sources.data = user.data_sources
    return render_template(
        "setup_user.jinja2",
        form=form,
        user=user,
        title="Group",
    )


@app.route("/logout")
@limiter.limit("60 per minute")
@login_required
def logout():
    audit = create_audit("logout", user=current_user)
    logout_user()
    finish_audit(audit, state="ok")
    return redirect(url_for("index"))


@app.route("/privacy")
@limiter.limit("60 per minute")
def privacy():
    return render_template("privacy.jinja2")


@app.route("/welcome")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def welcome():
    # not enabled and not banned and in no group
    not_activated_users = (
        db.session.query(User)
        .filter(
            and_(
                ~User.is_enabled,
                ~User.is_banned,
                User.group_id.is_(None),
            )
        )
        .order_by(desc(User.id))
        .all()
    )

    unresolved_problem_reports = (
        db.session.query(ProblemReport)
        .filter(ProblemReport.is_hidden == False)
        .order_by(desc(ProblemReport.id))
        .all()
    )

    return render_template(
        "welcome.jinja2",
        title=gettext("Welcome page"),
        not_activated_users=not_activated_users,
        unresolved_problem_reports=unresolved_problem_reports,
        now=datetime.datetime.utcnow(),
    )


def count_machines(mt):
    # counts how many running machines there are for the given template
    running_states = [
        MachineState.PROVISIONING,
        MachineState.READY,
        MachineState.DELETING,
    ]
    return (
        db.session.query(Machine)
        .filter(
            and_(
                Machine.machine_template == mt,
                Machine.state.in_(running_states),
            )
        )
        .count()
    )


@app.route("/machines")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def machines():
    """
    The machine page displays and controls the user's machines
    """
    if not current_user.ssh_keys:
        logging.info(f"user {current_user.id} is missing ssh keys, creating...")
        current_user.ssh_keys = gen_ssh_keys(current_user.id)
        db.session.commit()
        logging.info(f"ssh key added for {current_user.id} ok")

    # Query for user's owned machines
    owned_machines_query = db.session.query(Machine).filter(
        and_(
            Machine.owner == current_user,
            ~Machine.state.in_([MachineState.DELETED, MachineState.DELETING]),
        )
    )

    # Query for machines shared with the user
    shared_machines_query = (
        db.session.query(Machine)
        .join(shared_user_machine)
        .filter(
            and_(
                shared_user_machine.c.user_id == current_user.id,
                ~Machine.state.in_([MachineState.DELETED, MachineState.DELETING]),
            )
        )
    )

    # Combine the two queries with a UNION operation and order the result
    user_machines = (
        owned_machines_query.union(shared_machines_query)
        .order_by(Machine.id.desc())
        .all()
    )

    return render_template(
        "machines.jinja2",
        title=gettext("Machines"),
        count_machines=count_machines,
        user_machines=user_machines,
        MachineTemplate=MachineTemplate,
        MachineState=MachineState,
        Machine=Machine,
        now=datetime.datetime.utcnow(),
        machine_format_dtj=machine_format_dtj,
    )


def contains_non_alphanumeric_chars(string):
    # alphanum or -
    for char in string:
        if not char.isalnum() and char != "-":
            return True


@app.route("/rename_machine", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def rename_machine():
    # allow the user to rename a machine
    machine_id = request.form.get("machine_id")
    machine_new_display_name = request.form.get("machine_new_name")

    if not machine_new_display_name or not machine_id:
        flash(gettext("Invalid values for machine rename"), "danger")
        return redirect(url_for("machines"))

    if not is_name_safe(machine_new_display_name):
        flash(gettext("Invalid values for machine rename"), "danger")
        return redirect(url_for("machines"))
    try:
        machine_id = int(machine_id)
    except:
        flash(gettext("Invalid values for machine rename"), "danger")
        return redirect(url_for("machines"))

    if len(machine_new_display_name) <= 3 or len(machine_new_display_name) > 99:
        flash(gettext("New name must be between 4 and 99 characters long"), "danger")
        return redirect(url_for("machines"))

    machine = Machine.query.filter_by(id=machine_id).first()
    if not machine:
        flash(gettext("Machine to rename not found"), "danger")
        return redirect(url_for("machines"))

    # TODO: check if the new name includes a username other than CU.name

    old_display_name = machine.display_name
    machine.display_name = machine_new_display_name
    db.session.commit()

    flash(f"Machine {old_display_name} renamed to {machine_new_display_name}")
    return redirect(url_for("machines"))


@app.route("/get_machine_state/<machine_id>")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def get_machine_state(machine_id):
    machine = Machine.query.filter_by(id=machine_id).first()
    if not machine or not (
        current_user in machine.shared_users or current_user == machine.owner
    ):
        return {"machine_state": None}
    return {"machine_state": str(machine.state)}


@app.route("/admin")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for("login"))

    return render_template(
        "admin.jinja2",
        title=gettext("Admin"),
        Group=Group,
        env=os.environ,
    )


@app.route("/citations")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def citations():
    return render_template("citations.jinja2", title=gettext("Citations"))


@app.route("/about")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def about():
    return render_template("about.jinja2", title=gettext("About"))


@app.route("/help")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def help():
    return render_template("help.jinja2", title=gettext("Help"))


@app.route("/landing")
@limiter.limit("60 per minute")
def landing():
    return render_template("landing.jinja2", title=gettext("Ada Data Analysis"))


class ProblemReportForm(FlaskForm):
    title = StringField(lazy_gettext("Title"), validators=[DataRequired()])
    description = TextAreaField(lazy_gettext("Description"), validators=[])
    machine_id = HiddenField("machine_id")
    data_transfer_job_id = HiddenField("data_transfer_job_id")
    submit = SubmitField(lazy_gettext("Submit"))


@app.route("/report_problem", methods=["GET", "POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def report_problem():
    form = ProblemReportForm()
    if request.method == "POST":
        if form.validate_on_submit():
            machine_id = form.machine_id.data
            data_transfer_job_id = form.data_transfer_job_id.data

            # no checking - these can be null
            machine = Machine.query.filter_by(id=machine_id).first()
            data_transfer_job = DataTransferJob.query.filter_by(
                id=data_transfer_job_id
            ).first()

            problem_report = ProblemReport(
                title=form.title.data,
                description=form.description.data,
                user=current_user,
                machine=machine,
                data_transfer_job=data_transfer_job,
            )
            db.session.add(problem_report)
            db.session.commit()
            flash(gettext("Problem report submitted successfully."), "success")
            return redirect(url_for("index"))
    else:
        form.machine_id.data = request.args.get("machine_id")
        form.data_transfer_job_id.data = request.args.get("data_transfer_job_id")
        form.title.data = request.args.get("title")
        return render_template(
            "report_problem.jinja2",
            title=gettext("Help"),
            form=form,
        )


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


class DataTransferForm(FlaskForm):
    data_source = SelectField(
        lazy_gettext("Data Source"), validators=[DataRequired()], coerce=int
    )
    machine = SelectField(
        lazy_gettext("Destination Machine"), validators=[DataRequired()], coerce=int
    )
    submit_data_transfer = SubmitField(lazy_gettext("Submit"))


class MachineTransferForm(FlaskForm):
    machine = SelectField(
        lazy_gettext("Source Machine"), validators=[DataRequired()], coerce=int
    )
    machine2 = SelectField(
        lazy_gettext("Destination Machine"), validators=[DataRequired()], coerce=int
    )
    submit_machine_transfer = SubmitField(lazy_gettext("Submit"))


@app.route("/dismiss_datatransferjob", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def dismiss_datatransferjob():
    """
    Endpoint for hiding the data transfer job from the data page
    by setting its state to HIDDEN
    """
    job_id = request.form.get("job_id")
    if not job_id:
        abort(404)

    job = DataTransferJob.query.filter_by(id=job_id).first()

    if not job:
        abort(404)

    if job.user != current_user:
        abort(403)

    job.state = DataTransferJobState.HIDDEN
    db.session.commit()
    return "OK"


def machine_format_dtj(machine):
    """
    Returns a set of unique formatted data transfer job entries for a specific machine.
    """
    Source = aliased(DataSource)
    jobs = (
        DataTransferJob.query.join(Source, DataTransferJob.data_source)
        .filter(
            and_(
                DataTransferJob.machine == machine,
                DataTransferJob.state == DataTransferJobState.DONE,
            )
        )
        .with_entities(Source.name)
        .distinct()
    )

    return {job[0] for job in jobs}


@app.route("/data", methods=["GET", "POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def data():
    # admin or normal user
    if current_user.is_admin:
        # the admin can use all data sources
        data_sources = DataSource.query.all()
        # the admin can copy data sources into any machine
        machines = (
            Machine.query.filter(Machine.state == MachineState.READY)
            .order_by(desc(Machine.id))
            .all()
        )

    else:
        # user's data sources
        data_sources = current_user.data_sources
        # machines they can copy data sources into
        machines = (
            Machine.query.filter(
                and_(
                    Machine.state == MachineState.READY,
                    or_(
                        Machine.owner_id == current_user.id,
                        Machine.shared_users.any(id=current_user.id),
                    ),
                )
            )
            .order_by(desc(Machine.id))
            .all()
        )

    # machines users can transfer their shared folder from/to
    # (does not include shared machines due to ssh key limitations)
    machines2 = (
        Machine.query.filter(
            and_(
                Machine.state == MachineState.READY,
                Machine.owner_id == current_user.id,
            )
        )
        .order_by(desc(Machine.id))
        .all()
    )

    # fill in the form select options
    data_transfer_form = DataTransferForm()
    machine_transfer_form = MachineTransferForm()

    data_transfer_form.data_source.choices = [
        (ds.id, f"{ds.name} ({ds.data_size} MB)") for ds in data_sources
    ]
    data_transfer_form.machine.choices = [(m.id, m.display_name) for m in machines]

    machine_transfer_form.machine.choices = [(m.id, m.display_name) for m in machines2]
    machine_transfer_form.machine2.choices = list(
        reversed(machine_transfer_form.machine.choices)
    )

    if request.method == "POST":
        # form POST

        audit = create_audit("data transfer", user=current_user)
        form1_ok = False
        form2_ok = False

        #
        # Machine to machine data transfer form
        #
        if (
            machine_transfer_form.validate_on_submit()
            and machine_transfer_form.submit_machine_transfer.data
        ):
            form1_ok = True
            machine = Machine.query.filter_by(
                id=machine_transfer_form.machine.data
            ).first()
            machine2 = Machine.query.filter_by(
                id=machine_transfer_form.machine2.data
            ).first()

            if not machine or not machine2:
                finish_audit(audit, "bad args")
                abort(404)

            if machine not in machines2 or machine2 not in machines2:
                finish_audit(audit, "bad permissions")
                abort(403)

            if machine.id == machine2.id:
                flash(gettext("You can't transfer from a machine to itself."), "danger")
                finish_audit(audit, "bad form")
                return redirect(url_for("data"))

            # checks ok

            job = DataTransferJob(
                machine_id=machine.id,
                machine2_id=machine2.id,
                state=DataTransferJobState.RUNNING,
                user=current_user,
            )
            # TODO allow users to change this
            copy_dir_path = "/home/ubuntu/"

            db.session.add(job)
            db.session.commit()

            threading.Thread(
                target=start_machine_transfer, args=(job.id, audit.id, copy_dir_path)
            ).start()

            flash(gettext("Starting machine data transfer."))

            return redirect(url_for("data"))

        #
        # Data transfer form
        #
        if (
            data_transfer_form.validate_on_submit()
            and data_transfer_form.submit_data_transfer.data
        ):
            form2_ok = True
            machine = Machine.query.filter_by(
                id=data_transfer_form.machine.data
            ).first()
            data_source = DataSource.query.filter_by(
                id=data_transfer_form.data_source.data
            ).first()

            if not machine or not data_source:
                finish_audit(audit, "bad args")
                abort(404)

            if machine not in machines or data_source not in data_sources:
                finish_audit(audit, "bad permissions")
                abort(403)

            # security checks ok

            job = DataTransferJob(
                state=DataTransferJobState.RUNNING,
                user=current_user,
                data_source=data_source,
                machine=machine,
            )
            update_audit(audit, machine=machine, data_transfer_job=job)
            db.session.add(job)
            db.session.commit()
            threading.Thread(
                target=start_data_transfer, args=(job.id, audit.id)
            ).start()

            flash(gettext("Starting data transfer. Refresh page to update status."))
            return redirect(url_for("data"))

        if not (form1_ok or form2_ok):
            finish_audit(audit, "bad form")
            flash(
                gettext("The transfer job submission could not be validated."), "danger"
            )
            return redirect(url_for("data"))

    else:
        # GET
        sorted_jobs = (
            DataTransferJob.query.filter(DataTransferJob.user_id == current_user.id)
            .filter(DataTransferJob.state != DataTransferJobState.HIDDEN)
            .order_by(desc(DataTransferJob.id))
            .all()
        )
        return render_template(
            "data.jinja2",
            title=gettext("Data"),
            data_transfer_form=data_transfer_form,
            machine_transfer_form=machine_transfer_form,
            sorted_jobs=sorted_jobs,
        )


@log_function_call
def do_rsync(source_host, source_port, source_dir, dest_host, dest_dir, key_path=None):
    try:
        key_cmd = ""
        if key_path:
            key_cmd = f"-i {key_path}"

        # Construct the rsync command
        rsync_cmd = (
            f"rsync --include='/*/.*' --exclude='/.*' -avz -e 'ssh {key_cmd} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' "
            f"{source_dir} {dest_host}:{dest_dir}"
        )
        logging.info(rsync_cmd)

        # Construct the ssh command to run the rsync command on the source_host
        ssh_cmd = (
            f"ssh -p {source_port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
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


@log_function_call
def start_data_transfer(job_id, audit_id):
    """
    Thread function that takes a job and runs the data transfer
    """
    with app.app_context():
        audit = get_audit(audit_id)
        result = None
        job = DataTransferJob.query.filter_by(id=job_id).first()
        if not job:
            finish_audit(audit, "bad job id")
            logging.error(f"job {job_id} not found!")
        else:
            result = do_rsync(
                source_host=f"{job.data_source.source_username}@{job.data_source.source_host}",
                source_port=job.data_source.source_port,
                source_dir=job.data_source.source_dir,
                dest_host=f"{job.machine.machine_template.os_username}@{job.machine.ip}",
                dest_dir="",
            )

        if result:
            finish_audit(audit, "ok")
            job.state = DataTransferJobState.DONE
        else:
            finish_audit(audit, "error")
            job.state = DataTransferJobState.FAILED
        db.session.commit()


@log_function_call
def start_machine_transfer(job_id, audit_id, copy_dir_path):
    """
    Thread function that takes a job and copies some directory between machines
    """
    with app.app_context():
        audit = get_audit(audit_id)
        result = None
        job = DataTransferJob.query.filter_by(id=job_id).first()
        if not job:
            finish_audit(audit, "bad job id")
            logging.error(f"job {job_id} not found!")
        else:
            result = do_rsync(
                source_host=f"ubuntu@{job.machine.ip}",
                source_port=22,
                source_dir=copy_dir_path,
                dest_host=f"ubuntu@{job.machine2.ip}",
                dest_dir=copy_dir_path,
                key_path="/home/ubuntu/.ssh/ada-id_rsa",
            )

        if result:
            finish_audit(audit, "ok")
            job.state = DataTransferJobState.DONE
        else:
            finish_audit(audit, "error")
            job.state = DataTransferJobState.FAILED
        db.session.commit()


@app.route("/share_machine/<machine_id>")
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def share_machine(machine_id):
    """
    Shows the share page
    """
    try:
        machine_id = int(machine_id)
    except:
        abort(404)

    machine = Machine.query.filter_by(id=machine_id).first_or_404()

    perm_ok = current_user == machine.owner or current_user in machine.shared_users

    if not perm_ok:
        flash("You can't share that machine", "danger")
        return redirect(url_for("welcome"))

    s = URLSafeTimedSerializer(ADA2025_SHARE_TOKEN_SECRET_KEY)
    timed_share_token = s.dumps(machine.share_token)

    return render_template(
        "share.jinja2",
        title=gettext("Machines"),
        machine=machine,
        timed_share_token=timed_share_token,
    )


@app.route("/share_accept/<timed_share_token>")
@limiter.limit("60 per hour")
@login_required
@profile_complete_required
def share_accept(timed_share_token):
    """
    This is the endpoint hit by the user accepting a share
    """
    audit = create_audit("share accept", user=current_user)

    s = URLSafeTimedSerializer(ADA2025_SHARE_TOKEN_SECRET_KEY)
    try:
        share_token = s.loads(timed_share_token, max_age=1800)  # in seconds
    except Exception as e:
        logging.warning(f"token exception: {e}")
        flash(
            "That share link has expired. Please request a new one from the machine's owner.",
            "danger",
        )
        finish_audit(audit, "invalid token")
        return redirect(url_for("machines"))

    machine = Machine.query.filter_by(share_token=share_token).first()

    if not machine:
        finish_audit(audit, "bad token")
        flash(gettext("Machine not found."))
        return redirect(url_for("machines"))
    else:
        update_audit(audit, state="running", machine=machine)

    if current_user == machine.owner:
        finish_audit(audit, "is owner")
        flash(gettext("You own that machine."))
        return redirect(url_for("machines"))
    if current_user in machine.shared_users:
        finish_audit(audit, "already shared")
        flash(gettext("You already have that machine."))
        return redirect(url_for("machines"))

    machine.shared_users.append(current_user)
    db.session.commit()
    finish_audit(audit, "ok")
    flash(gettext("Shared machine has been added to your account."))
    return redirect(url_for("machines"))


@app.route("/share_revoke/<machine_id>")
@limiter.limit("60 per hour")
@login_required
@profile_complete_required
def share_revoke(machine_id):
    """
    The owner revokes all shares. We do this by removing shared_users
    and resetting the machine share token
    """
    audit = create_audit("share revoke", user=current_user)
    machine = Machine.query.filter_by(id=machine_id).first()
    if not machine:
        finish_audit(audit, "no machine")
        flash(gettext("That machine could not be found"), "danger")
        return redirect(url_for("machines"))

    update_audit(audit, machine=machine)

    if current_user != machine.owner:
        finish_audit(audit, "not owner")
        flash(gettext("You can't revoke shares on a machine you don't own."), "danger")
        return redirect(url_for("machines"))

    machine.share_token = gen_token(16)
    machine.shared_users = []
    finish_audit(audit, "ok")
    db.session.commit()
    flash(
        gettext(
            "Shares for machine have been removed and a new share link has been generated"
        )
    )
    return redirect(url_for("machines"))


@app.route("/metrics")
def metrics():
    machines_counts = collections.defaultdict(int)
    audits_counts = collections.defaultdict(int)
    users_counts = collections.defaultdict(int)

    # Perform a join on Machine and MachineTemplate
    machines = (
        db.session.query(Machine, MachineTemplate)
        .join(MachineTemplate, Machine.machine_template_id == MachineTemplate.id)
        .all()
    )

    machines_var_names = [
        "group_id",
        "machine_template_id",
        "machine_template_type",
        "owner_id",
        "machine_template_cpu",
        "machine_template_mem",
        "machine_template_disk_gb",
        "state",
    ]
    for machine, machine_template in machines:
        machines_counts[
            (
                machine_template.group_id,
                machine_template.id,
                machine_template.type,
                machine.owner_id,
                machine_template.cpu_limit_cores,
                machine_template.memory_limit_gb,
                machine_template.disk_size_gb,
                machine.state,
            )
        ] += 1

    audit_var_names = [
        "user_id",
        "action_name",
        "state_name",
    ]
    for audit in Audit.query.all():
        audits_counts[
            (
                audit.user_id,
                audit.action,
                audit.state,
            )
        ] += 1

    user_var_names = [
        "is_enabled",
        "group_id",
    ]
    for user in User.query.all():
        users_counts[
            (
                user.is_enabled,
                user.group_id,
            )
        ] += 1

    out = ""

    for count_keys, machines_count in machines_counts.items():
        labels_dict = {
            var_name: key for var_name, key in zip(machines_var_names, count_keys)
        }
        labels_str = ", ".join(f'{k}="{v}"' for k, v in labels_dict.items())
        out += f"machines{{{labels_str}}} {machines_count}\n"

    for count_keys, audits_count in audits_counts.items():
        labels_dict = {
            var_name: key for var_name, key in zip(audit_var_names, count_keys)
        }
        labels_str = ", ".join(f'{k}="{v}"' for k, v in labels_dict.items())
        out += f"audit{{{labels_str}}} {audits_count}\n"

    for count_keys, users_count in users_counts.items():
        labels_dict = {
            var_name: key for var_name, key in zip(user_var_names, count_keys)
        }
        labels_str = ", ".join(f'{k}="{v}"' for k, v in labels_dict.items())
        out += f"user{{{labels_str}}} {users_count}\n"

    return out


@app.route("/new_machine", methods=["POST"])
@limiter.limit("100 per day, 10 per minute, 1/3 seconds")
@login_required
@profile_complete_required
def new_machine():
    """
    Launches thread to create the container/vm
    """
    machine_template_id = request.form.get("machine_template_id", "")
    audit = create_audit("create machine", user=current_user)

    mt = MachineTemplate.query.filter_by(id=machine_template_id).first()
    if not mt:
        finish_audit(audit, "bad mt")
        flash("You can't launch that machine template")
        return redirect(url_for("machines"))

    if quota := mt.extra_data.get("quota"):
        if count_machines(mt) >= quota:
            finish_audit(audit, "template quota exceeded")
            flash("Quota for template exceeded", "danger")
            return redirect(url_for("machines"))

    machine_name = mk_safe_machine_name(current_user.username)

    m = Machine(
        name=machine_name,
        display_name=machine_name,
        ip="",
        state=MachineState.PROVISIONING,
        owner=current_user,
        shared_users=[],
        machine_template=mt,
    )
    update_audit(audit, machine=m)

    logging.info("starting new machine thread")

    if mt.type == "docker":
        target = DockerService.start
    elif mt.type == "libvirt":
        target = LibvirtService.start
    elif mt.type == "openstack":
        target = OpenStackService.start
    else:
        raise RuntimeError(mt.type)

    db.session.add(m)
    db.session.commit()

    threading.Thread(target=target, args=(m.id, audit.id)).start()
    flash(
        gettext("Creating machine."),
        category="success",
    )
    return redirect(url_for("machines"))


@app.route("/shutdown_machine", methods=["POST"])
@limiter.limit("100 per day, 10 per minute, 1/3 seconds")
@login_required
@profile_complete_required
def shutdown_machine():
    """
    Start thread to shutdown machine
    """

    # sanity checks
    audit = create_audit("shutdown machine", user=current_user)
    machine_id = request.form.get("machine_id")

    if not machine_id:
        finish_audit(audit, "machine_id missing")
        logging.warning(f"machine_id parameter missing: {machine_id}")
        abort(404)

    try:
        machine_id = int(machine_id)
    except Exception:
        finish_audit(audit, "machine_id bad")
        logging.warning(f"machine_id not int: {machine_id}")
        abort(404)

    m = Machine.query.filter_by(id=machine_id).first()
    if not m:
        finish_audit(audit, "machine not found")
        abort(404)

    update_audit(audit, machine=m)

    if not current_user.is_admin and not current_user == m.owner:
        finish_audit(audit, "bad user")
        logging.warning(
            f"user {current_user.id} is not the owner of machine {machine_id} nor admin"
        )
        abort(403)
    if m.state != MachineState.READY:
        logging.warning(
            f"machine {machine_id} is not in correct state for shutdown: {m.state}"
        )

    mt = m.machine_template

    if mt.type == "docker":
        raise NotImplementedError(mt.type)
    elif mt.type == "libvirt":
        raise NotImplementedError(mt.type)
    elif mt.type == "openstack":
        target = OpenStackService.shut_down
    else:
        raise RuntimeError(mt.type)

    m.state = MachineState.STOPPING
    db.session.commit()

    threading.Thread(target=target, args=(m.id, audit.id)).start()
    flash(gettext("Shutting down machine"), category="success")
    return redirect(url_for("machines"))


@app.route("/resume_machine", methods=["POST"])
@limiter.limit("100 per day, 10 per minute, 1/3 seconds")
@login_required
@profile_complete_required
def resume_machine():
    """
    Start thread to resume machine
    """

    # sanity checks
    audit = create_audit("resume machine", user=current_user)
    machine_id = request.form.get("machine_id")

    if not machine_id:
        finish_audit(audit, "machine_id missing")
        logging.warning(f"machine_id parameter missing: {machine_id}")
        abort(404)

    try:
        machine_id = int(machine_id)
    except Exception:
        finish_audit(audit, "machine_id bad")
        logging.warning(f"machine_id not int: {machine_id}")
        abort(404)

    m = Machine.query.filter_by(id=machine_id).first()
    if not m:
        finish_audit(audit, "machine not found")
        abort(404)

    update_audit(audit, machine=m)

    if not current_user.is_admin and not current_user == m.owner:
        finish_audit(audit, "bad user")
        logging.warning(
            f"user {current_user.id} is not the owner of machine {machine_id} nor admin"
        )
        abort(403)
    if m.state != MachineState.STOPPED:
        logging.warning(
            f"machine {machine_id} is not in correct state for resuming: {m.state}"
        )

    mt = m.machine_template

    if mt.type == "docker":
        raise NotImplementedError(mt.type)
    elif mt.type == "libvirt":
        raise NotImplementedError(mt.type)
    elif mt.type == "openstack":
        target = OpenStackService.resume
    else:
        raise RuntimeError(mt.type)

    m.state = MachineState.STARTING
    db.session.commit()

    threading.Thread(target=target, args=(m.id, audit.id)).start()

    flash(gettext("Resuming machine."), category="success")
    return redirect(url_for("machines"))


@app.route("/stop_machine", methods=["POST"])
@limiter.limit("100 per day, 10 per minute, 1/3 seconds")
@login_required
@profile_complete_required
def stop_machine():
    """
    Start thread to stop machine
    """

    # sanity checks
    audit = create_audit("stop machine", user=current_user)
    machine_id = request.form.get("machine_id")

    if not machine_id:
        finish_audit(audit, "machine_id missing")
        logging.warning(f"machine_id parameter missing: {machine_id}")
        abort(404)

    try:
        machine_id = int(machine_id)
    except Exception:
        finish_audit(audit, "machine_id bad")
        logging.warning(f"machine_id not int: {machine_id}")
        abort(404)

    machine = Machine.query.filter_by(id=machine_id).first()
    if not machine:
        finish_audit(audit, "machine not found")
        abort(404)

    update_audit(audit, machine=machine)

    if not current_user.is_admin and not current_user == machine.owner:
        finish_audit(audit, "bad user")
        logging.warning(
            f"user {current_user.id} is not the owner of machine {machine.id} nor admin"
        )
        abort(403)
    if machine.state not in [
        MachineState.READY,
        MachineState.FAILED,
    ]:
        logging.warning(
            f"machine {machine.id} is not in correct state for deletion: {machine.state}"
        )
        flash(
            gettext("Machine cannot be stopped in its current state."),
            category="danger",
        )
        return redirect(url_for("machines"))

    # let's go
    stop_machine2(machine.id, audit.id)

    flash(gettext("Deleting machine"), category="success")
    return redirect(url_for("machines"))


def stop_machine2(machine_id, audit_id=None):
    # we split this off into a separate function so it can be called
    # in flask-admin actions

    if not audit_id:
        audit = create_audit("stop machine", user=current_user)
    else:
        audit = Audit.query.filter_by(id=audit_id).first()

    machine = Machine.query.filter_by(id=machine_id).first()

    update_audit(audit, machine=machine)

    if machine.machine_template.type == "docker":
        target = DockerService.stop
    elif machine.machine_template.type == "libvirt":
        target = LibvirtService.stop
    elif machine.machine_template.type == "openstack":
        target = OpenStackService.stop
    else:
        raise RuntimeError(machine.machine_template.type)

    # good to go
    logging.info(f"deleting machine with machine id {machine_id}")
    machine.state = MachineState.DELETING
    db.session.commit()

    threading.Thread(target=target, args=(machine.id, audit.id)).start()


@app.route("/unshare_machine_from_self", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def unshare_machine_from_self():
    # sanity checks
    audit = create_audit("unshare machine from self", user=current_user)
    machine_id = request.form.get("machine_id")

    if not machine_id:
        finish_audit(audit, "machine_id missing")
        logging.warning(f"machine_id parameter missing: {machine_id}")
        abort(404)

    try:
        machine_id = int(machine_id)
    except Exception:
        finish_audit(audit, "machine_id bad")
        logging.warning(f"machine_id not int: {machine_id}")
        abort(404)

    machine = Machine.query.filter_by(id=machine_id).first()
    if not machine:
        finish_audit(audit, "machine not found")
        abort(404)

    update_audit(audit, machine=machine)

    if current_user == machine.owner:
        finish_audit(audit, "bad user")
        logging.warning(
            f"user {current_user.id} is the owner of machine {machine.id} - can't unshare from self."
        )
        abort(403)

    # perform action
    logging.info(
        f"Removing access for user {current_user} from machine with machine id {machine.id}"
    )
    machine.shared_users.remove(current_user)
    db.session.commit()

    flash(gettext("Removed machine from list"), category="success")
    return redirect(url_for("machines"))


@app.route("/unshare_machine", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
@profile_complete_required
def unshare_machine():
    user_id = request.json.get("user_id")
    machine_id = request.json.get("machine_id")

    if not user_id:
        abort(404)

    if not machine_id:
        abort(404)

    user = User.query.filter_by(id=user_id).first_or_404()
    machine = Machine.query.filter_by(id=machine_id).first_or_404()

    perm_ok = machine.owner == current_user
    if not perm_ok:
        abort(403)

    machine.shared_users.remove(user)
    db.session.commit()

    return "OK"


@log_function_call
def run_machine_command(machine, command):
    escaped_command = shlex.quote(command)
    host = f"{machine.machine_template.os_username}@{machine.ip}"
    cmd = f"ssh -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no {host} bash -c {escaped_command}"
    logging.info(f"running command: {cmd}")

    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()

    logging.debug(f"stdout: {stdout}")
    logging.debug(f"stderr: {stderr}")

    if process.returncode != 0:
        raise RuntimeError("Command failed")


@log_function_call
def wait_for_nginx(machine, timeout=120):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            ssh.connect(machine.ip, username=machine.machine_template.os_username)
            stdin, stdout, stderr = ssh.exec_command("ps -A | grep [n]ginx")
            output = stdout.read().decode().strip()

            if "nginx" in output:
                logging.info("Nginx process found, the VM seems ready.")
                break
            else:
                logging.info("Nginx process not found, retrying in 5 seconds...")
                time.sleep(5)

        except Exception as e:
            logging.info(f"wait_for_nginx: looping again: {str(e)}")
            time.sleep(5)

        finally:
            ssh.close()


@log_function_call
def configure_nginx(machine, service_type="systemd"):
    # this function replaces the nginx access token and sets a new cookie value
    # it can be used on machine set up, and when we want to kick users out

    wait_for_nginx(machine)

    new_access_token = machine.access_token
    new_cookie_value = gen_token(16)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())

    # Connect to the remote machine
    ssh.connect(machine.ip, username=machine.machine_template.os_username)
    sftp = ssh.open_sftp()

    # Fetch the existing configuration
    sftp.get(
        "/etc/nginx/sites-enabled/nginx-ada.conf", f"{new_access_token}_nginx.conf"
    )

    # Replace the placeholders in the configuration
    with open(f"{new_access_token}_nginx.conf", "r") as f:
        config = f.read()

    config = re.sub(
        r"location /[a-zA-Z0-9]{16} ",
        rf"location /{new_access_token} ",
        config,
    )
    config = re.sub(
        r"session=[a-zA-Z0-9]{16};",
        rf"session={new_cookie_value};",
        config,
    )
    config = re.sub(
        r'cookie_session != "[a-zA-Z0-9]{16}"',
        rf'cookie_session != "{new_cookie_value}"',
        config,
    )
    config = re.sub(
        r"limit_req zone=mylimit;",
        r"limit_req zone=mylimit burst=30 nodelay;",
        config,
    )

    with open(f"{new_access_token}_nginx.conf", "w") as f:
        f.write(config)

    # Upload the new configuration to a temporary location in the remote machine
    sftp.put(f"{new_access_token}_nginx.conf", "/tmp/nginx.conf")

    # Use sudo to move the configuration to its final location
    stdin, stdout, stderr = ssh.exec_command(
        "sudo mv /tmp/nginx.conf /etc/nginx/sites-enabled/nginx-ada.conf"
    )
    exit_status = stdout.channel.recv_exit_status()  # Wait for exec_command to finish

    # Restart nginx
    if service_type == "systemd":
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl restart nginx")
        exit_status = (
            stdout.channel.recv_exit_status()
        )  # Wait for exec_command to finish
    elif service_type == "direct":
        stdin, stdout, stderr = ssh.exec_command(
            "sudo pkill -QUIT nginx && sudo nohup nginx &"
        )
        exit_status = (
            stdout.channel.recv_exit_status()
        )  # Wait for exec_command to finish

    sftp.close()
    ssh.close()


class VirtService(ABC):
    @staticmethod
    def set_app(app):
        # maybe the parts that need the app context should be abstracted into callbacks, or maybe that TOO abstract
        VirtService.app = app

    @staticmethod
    @abstractmethod
    def start(m_id: int, audit_id: int):
        pass

    @staticmethod
    @abstractmethod
    def stop(m_id: int, audit_id: int):
        pass


class OpenStackService(VirtService):
    # Function to create a new VM from an image
    @log_function_call
    @staticmethod
    def start(m_id: int, audit_id):
        with OpenStackService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider

                vm_name = m.name
                flavor_name = mt.extra_data.get("flavor_name")
                network_uuid = mt.extra_data.get("network_uuid")
                vol_size = mt.extra_data.get("vol_size")
                security_groups = mt.extra_data.get("security_groups", [])
                vol_image = mt.image.name

                conn, env = OpenStackService.conn_from_mp(mp)

                # Find the network by UUID
                network = conn.network.get_network(network_uuid)
                if not network:
                    raise ValueError(f"OpenStack network {network_uuid} not found.")

                # Find the flavor by name
                flavor = conn.compute.find_flavor(flavor_name)
                if not flavor:
                    raise ValueError(f"OpenStack flavor {flavor_name} not found.")

                image = conn.compute.find_image(vol_image)
                if not image:
                    raise ValueError(f"OpenStack image {vol_image} not found.")

                if vol_size:
                    # Create a bootable volume from the specified image
                    cinder = cinderclient.Client("3", session=conn.session)

                    volume = cinder.volumes.create(
                        size=vol_size,
                        imageRef=image.id,
                        name=f"{vm_name}_boot",
                    )

                    OpenStackService.wait_for_volume(env, volume.id)

                    # Create the server (VM)
                    server = conn.compute.create_server(
                        name=vm_name,
                        flavor_id=flavor.id,
                        networks=[{"uuid": network_uuid}],
                        security_groups=security_groups,
                        block_device_mapping_v2=[
                            {
                                "boot_index": "0",
                                "uuid": volume.id,
                                "source_type": "volume",
                                "destination_type": "volume",
                                "delete_on_termination": True,
                            }
                        ],
                    )
                else:
                    server = conn.compute.create_server(
                        name=vm_name,
                        flavor_id=flavor.id,
                        networks=[{"uuid": network_uuid}],
                        security_groups=security_groups,
                        image_id=image.id,
                    )

                OpenStackService.wait_for_vm_state(
                    env, server.id, "ACTIVE", timeout=2400
                )

                # wait for an ip
                m.ip = OpenStackService.wait_for_vm_ip(conn, server.id, network.id)

                time.sleep(2)

                # assign floating ip if configured
                if mt.extra_data.get("assign_floating_ip"):
                    m.ip = OpenStackService.assign_floating_ip(env, server.id)

                # try to get the hostname, if the ip has one
                try:
                    m.hostname = get_hostname(m.ip)
                except:
                    logging.warning(f"Couldn't get openstack hostname for {m.ip}")
                    m.hostname = ""

                if hostname_postfix := mt.extra_data.get("hostname_postfix"):
                    m.hostname = (
                        misc.dnscrypto.encode_ip(m.ip, ADA2025_DNS_SECRET_KEY)
                        + hostname_postfix
                    )

                configure_nginx(m)
                keys.deploy_user_keys_to_machine(
                    m.ip,
                    m.owner.ssh_keys.private_key,
                    m.owner.ssh_keys.public_key,
                    m.owner.ssh_keys.authorized_keys,
                )

                m.state = MachineState.READY
                finish_audit(audit, "ok")
                db.session.commit()

            except Exception:
                finish_audit(audit, "failed")
                logging.exception("Couldn't start openstack vm: ")
                m.state = MachineState.FAILED
                db.session.commit()

    @staticmethod
    def stop(m_id: int, audit_id: int):
        with OpenStackService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider
                conn, _ = OpenStackService.conn_from_mp(mp)

                # Check if the server exists
                server = conn.compute.find_server(m.name)
                # Try to delete the server
                conn.compute.delete_server(server)
                finish_audit(audit, "ok")
                logging.info(f"OpenStack VM {m.name} deleted successfully.")

            except Exception:
                finish_audit(audit, "error")
                logging.exception("Couldn't stop openstack vm: ")
            m.state = MachineState.DELETED
            db.session.commit()

    @staticmethod
    def shut_down(m_id: int, audit_id: int):
        with OpenStackService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider
                conn, _ = OpenStackService.conn_from_mp(mp)

                server = conn.compute.find_server(m.name)
                conn.compute.stop_server(server)
                finish_audit(audit, "ok")
                logging.info(f"OpenStack VM {m.name} stopped successfully.")

            except Exception:
                m.state = MachineState.FAILED
                finish_audit(audit, "error")
                logging.exception("Couldn't shut down openstack vm: ")
            m.state = MachineState.STOPPED
            db.session.commit()

    @staticmethod
    def resume(m_id: int, audit_id: int):
        with OpenStackService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider
                conn, _ = OpenStackService.conn_from_mp(mp)

                server = conn.compute.find_server(m.name)
                conn.compute.start_server(server)
                finish_audit(audit, "ok")
                wait_for_nginx(m, timeout=600)
                logging.info(f"OpenStack VM {m.name} started successfully.")

            except Exception:
                m.state = MachineState.FAILED
                finish_audit(audit, "error")
                logging.exception("Couldn't resume openstack vm: ")
            m.state = MachineState.READY
            db.session.commit()

    @log_function_call
    @staticmethod
    def assign_floating_ip(env, server_id):
        # Get the list of all floating IPs
        get_ips_command = ["openstack", "floating ip", "list", "-f", "json"]
        result = subprocess.run(
            get_ips_command,
            check=True,
            text=True,
            capture_output=True,
            env=env,
        )
        ips = json.loads(result.stdout)

        # Filter the list to only include IPs that are not associated with any server
        available_ips = [ip for ip in ips if ip["Port"] is None]

        if not available_ips:
            raise Exception("No available floating IPs.")

        # Choose a random IP from the list of available IPs
        chosen_ip = secrets.choice(available_ips)

        # Add the chosen floating IP to the server
        add_ip_command = [
            "openstack",
            "server",
            "add",
            "floating",
            "ip",
            server_id,
            chosen_ip["Floating IP Address"],
        ]
        subprocess.run(add_ip_command, check=True, env=env)

        return chosen_ip["Floating IP Address"]

    @log_function_call
    @staticmethod
    def conn_from_mp(mp):
        auth_url = mp.provider_data.get("auth_url")
        user_domain_name = mp.provider_data.get("user_domain_name")
        project_domain_name = mp.provider_data.get("project_domain_name")
        username = mp.provider_data.get("username")
        password = mp.provider_data.get("password")
        project_name = mp.provider_data.get("project_name")

        env = {
            "OS_AUTH_URL": auth_url,
            "OS_USERNAME": username,
            "OS_PASSWORD": password,
            "OS_PROJECT_NAME": project_name,
            "OS_USER_DOMAIN_NAME": user_domain_name,
            "OS_PROJECT_DOMAIN_NAME": project_domain_name,
        }
        conn = openstack.connection.Connection(
            auth_url=auth_url,
            username=username,
            password=password,
            project_name=project_name,
            project_domain_name=project_domain_name,
            user_domain_name=user_domain_name,
        )

        return conn, env

    @log_function_call
    @staticmethod
    def wait_for_vm_ip(conn, server_id, network_uuid, timeout=600):
        # wait for the openstack vm to acquire an ip
        start_time = time.time()
        server = None

        # Get the network name using the network UUID
        network = conn.network.get_network(network_uuid)
        network_name = network.name

        while (duration := time.time() - start_time) < timeout:
            server = conn.compute.get_server(server_id)
            addresses = server.addresses.get(network_name, [])

            for address in addresses:
                if address.get("OS-EXT-IPS:type") == "fixed":
                    ip = address.get("addr")
                    logging.info(
                        f"OpenStack VM {server_id} got IP {ip} after {duration}"
                    )
                    return ip

            time.sleep(5)

        raise TimeoutError(
            f"OpenStack VM '{server_id}' did not get an IP address in {timeout}s."
        )

    @staticmethod
    def wait_for_volume(env, volume_id, timeout=1200):
        # wait for the openstack volume to be available
        start_time = time.time()

        while (duration := time.time() - start_time) < timeout:
            # Get volume details in JSON format
            volume_details_output = subprocess.check_output(
                ["openstack", "volume", "show", volume_id, "-f", "json"], env=env
            )
            volume_details = json.loads(volume_details_output)

            # Check volume status
            if volume_details["status"] == "available":
                logging.info(
                    f"OpenStack volume {volume_id} is available after {duration}s."
                )
                return volume_details

            logging.info(
                f"Volume {volume_id} is not available yet. Retrying in 5 seconds..."
            )
            time.sleep(5)

        raise TimeoutError(f"OpenStack VM volume {volume_id} timeout in {timeout}s.")

    @staticmethod
    def wait_for_vm_state(env, server_id, state, timeout=300):
        # wait for the vm to be ready
        # TODO stop looping if we get to an error state
        start_time = time.time()

        while (duration := time.time() - start_time) < timeout:
            # Get server details in JSON format
            server_details_output = subprocess.check_output(
                ["openstack", "server", "show", server_id, "-f", "json"], env=env
            )
            server_details = json.loads(server_details_output)

            # Check server status
            if server_details["status"] == state:
                logging.info(f"Server {server_id} is {state} after {duration}s.")
                return server_details

            logging.info(
                f"Server {server_id} is not {state} yet. Retrying in 5 seconds..."
            )
            time.sleep(5)

        raise TimeoutError(
            f"OpenStack VM '{server_id}' state not {state} in {timeout}s."
        )

    @log_function_call
    @staticmethod
    def get_vm_by_ip(conn, target_ip):
        # get the vm object from its ip
        servers = conn.compute.servers()

        for server in servers:
            addresses = server.addresses
            for network, network_addresses in addresses.items():
                for address in network_addresses:
                    ip = address.get("addr")
                    if ip == target_ip:
                        return server

        raise ValueError(f"Couldn't find VM with IP {target_ip}")


class DockerService(VirtService):
    @log_function_call
    @staticmethod
    def start(m_id: int, audit_id: int):
        logging.info("entered DockerService.start thread")
        with DockerService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider

                network = mp.provider_data.get("network")
                cpu_cores = mt.cpu_limit_cores
                mem_limit_gb = mt.memory_limit_gb

                docker_base_url = mp.provider_data.get("base_url")
                client = docker.DockerClient(docker_base_url)

                cpu_period = 100000
                cpu_quota = int(cpu_period * cpu_cores)
                mem_limit = f"{mem_limit_gb * 1024}m"  # Convert GB to MB

                # Define container options, including CPU and memory limits
                container_options = {
                    "name": m.name,
                    "image": mt.image.name,
                    "network": network,
                    "cpu_period": cpu_period,
                    "cpu_quota": cpu_quota,
                    "mem_limit": mem_limit,
                }
                logging.info(json.dumps(container_options, indent=4))

                # Start the container
                container = client.containers.run(
                    **container_options,
                    detach=True,
                )

                m.ip = DockerService.wait_for_ip(client, m.name, network)

                configure_nginx(m, service_type="direct")
                keys.deploy_user_keys_to_machine(
                    m.ip,
                    m.owner.ssh_keys.private_key,
                    m.owner.ssh_keys.public_key,
                    m.owner.ssh_keys.authorized_keys,
                )

                m.state = MachineState.READY
                finish_audit(audit, "ok")
                db.session.commit()
            except Exception:
                finish_audit(audit, "error")
                logging.exception("Error: ")
                try:
                    container.stop()
                except Exception:
                    logging.exception("Error: ")
                try:
                    container.remove()
                except Exception:
                    logging.exception("Error: ")

                m.state = MachineState.FAILED
                m.ip = ""
                db.session.commit()

        logging.warning("all done!")

    @log_function_call
    @staticmethod
    def stop(machine_id: int, audit_id: int):
        with DockerService.app.app_context():
            audit = get_audit(audit_id)
            try:
                machine = Machine.query.filter_by(id=machine_id).first()
                mt = machine.machine_template
                mp = mt.machine_provider

                network = mp.provider_data.get("network")
                machine_ip = machine.ip
                docker_base_url = mp.provider_data.get("base_url")
                client = docker.DockerClient(docker_base_url)

                try:
                    container = DockerService.get_container_by_ip(
                        client, machine.ip, network
                    )
                    logging.info(f"Found container for ip {machine.ip}")
                    container.stop()
                except Exception as e:
                    logging.exception("Error: Unknown error occurred")

                machine.state = MachineState.DELETED
                finish_audit(audit, "ok")
                db.session.commit()
                logging.info(f"deleted container with machine id {machine_id}")
            except Exception:
                finish_audit(audit, "error")
                logging.exception("Error stopping container: ")

    @log_function_call
    @staticmethod
    def get_container_by_ip(client, ip_address, network):
        # get the container object by its ip
        try:
            network = client.networks.get(network)
            containers = network.containers

            # Search for the container with the specified IP address
            for cont in containers:
                cont_ips = [
                    x["IPAddress"]
                    for x in cont.attrs["NetworkSettings"]["Networks"].values()
                ]
                if ip_address in cont_ips:
                    return cont

            raise ValueError(f"container for ip {ip_address} not found")

        except Exception as e:
            logging.exception(f"Error getting container from ip {ip_address}:")

    @log_function_call
    @staticmethod
    def get_ip(client, container_name, network):
        # get the ip of the container
        container = client.containers.get(container_name)
        maybe_ip = container.attrs["NetworkSettings"]["Networks"][network]["IPAddress"]
        return maybe_ip

    @staticmethod
    def wait_for_ip(client, container_name, network, timeout=300):
        # wait until the docker container has an ip
        start_time = time.time()

        while not (ip := DockerService.get_ip(client, container_name, network)):
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Waiting for IP timed out after {timeout} seconds")
            time.sleep(1)

        return ip


class LibvirtService(VirtService):
    @log_function_call
    @staticmethod
    def start(m_id: int, audit_id: int):
        """
        Start a vm and wait for it to have an ip
        """
        logging.info("entered LibvirtService.start thread")
        with LibvirtService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider

                qemu_url = mp.provider_data.get("base_url")

                name = m.name
                image = mt.image
                cores = mt.cpu_limit_cores
                mem = int(mt.memory_limit_gb) * 1024 * 1024

                # TODO rewrite the following to use python api
                # clone vm
                subprocess.run(
                    [
                        "virt-clone",
                        "--connect",
                        qemu_url,
                        "--original",
                        image.name,
                        "--name",
                        name,
                        "--auto-clone",
                    ]
                )

                # Set the CPU and memory limits
                subprocess.run(
                    [
                        "virsh",
                        "--connect",
                        qemu_url,
                        "setvcpus",
                        name,
                        str(cores),
                        "--config",
                        "--maximum",
                    ]
                )
                subprocess.run(
                    [
                        "virsh",
                        "--connect",
                        qemu_url,
                        "setvcpus",
                        name,
                        str(cores),
                        "--config",
                    ]
                )
                subprocess.run(
                    [
                        "virsh",
                        "--connect",
                        qemu_url,
                        "setmaxmem",
                        name,
                        str(mem),
                        "--config",
                    ]
                )
                subprocess.run(
                    [
                        "virsh",
                        "--connect",
                        qemu_url,
                        "setmem",
                        name,
                        str(mem),
                        "--config",
                    ]
                )

                # start vm
                subprocess.run(["virsh", "--connect", qemu_url, "start", name])

                conn = libvirt.open(qemu_url)
                logging.info(f"waiting for vm {name} to come up")
                LibvirtService.wait_for_vm(conn, name)
                logging.info(f"vm {name} is up, waiting for ip")
                ip = LibvirtService.wait_for_ip(conn, name)
                logging.info(f"vm {name} has acquired an ip: {ip}")

                m.ip = ip
                m.state = MachineState.READY

                configure_nginx(m)
                keys.deploy_user_keys_to_machine(
                    m.ip,
                    m.owner.ssh_keys.private_key,
                    m.owner.ssh_keys.public_key,
                    m.owner.ssh_keys.authorized_keys,
                )

                finish_audit(audit, "ok")
                db.session.commit()
            except Exception:
                finish_audit(audit, "error")
                logging.exception("Error creating libvirt vm: ")
                m.state = MachineState.FAILED
                db.session.commit()

    @log_function_call
    @staticmethod
    def stop(m_id: int, audit_id: int):
        with LibvirtService.app.app_context():
            audit = get_audit(audit_id)
            try:
                m = Machine.query.filter_by(id=m_id).first()
                mt = m.machine_template
                mp = mt.machine_provider
                vm_name = m.name
                qemu_base_url = mp.provider_data.get("base_url")

                # Create a new connection to a local libvirt session
                conn = libvirt.open(qemu_base_url)

                # Stop the virtual machine
                domain = conn.lookupByName(vm_name)
                domain.destroy()

                # Delete the disk
                storage_paths = []
                for pool in conn.listAllStoragePools():
                    for vol in pool.listAllVolumes():
                        if vm_name in vol.name():
                            storage_paths.append(vol.path())
                            vol.delete(0)

                domain.undefine()
                finish_audit(audit, "ok")
                conn.close()
            except Exception:
                finish_audit(audit, "error")
                logging.exception("Error stopping libvirt vm:")
            m.state = MachineState.DELETED
            db.session.commit()

        logging.info(f"Stopped virtual machine {vm_name} and deleted its disk")

    @log_function_call
    @staticmethod
    def get_vm_ip(conn, vm_name):
        domain = conn.lookupByName(vm_name)

        interfaces = domain.interfaceAddresses(
            libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
        )

        for _, interface in interfaces.items():
            for address in interface["addrs"]:
                if address["type"] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                    logging.info(f"vm {vm_name} acquired ip: {address['addr']}")
                    return address["addr"]

        return None

    @log_function_call
    @staticmethod
    def wait_for_ip(conn, vm_name, timeout=300):
        start_time = time.time()

        while not (ip := LibvirtService.get_vm_ip(conn, vm_name)):
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Waiting for IP timed out after {timeout} seconds")
            time.sleep(1)

        return ip

    @log_function_call
    @staticmethod
    def wait_for_vm(conn, vm_name, timeout=600):
        # Wait for the virtual machine to be in the running state
        domain = conn.lookupByName(vm_name)

        start_time = time.time()
        while (duration := time.time() - start_time) < timeout:
            state, _ = domain.state()
            if state == libvirt.VIR_DOMAIN_RUNNING:
                logging.info(f"libvirt vm {vm_name} up after {duration}s")
                return
            time.sleep(1)

        raise TimeoutError(f"Waiting for VM {vm_name} timed out after {timeout}s")


def create_initial_db():
    # add initial data for testing
    # this will also print the passwords so you can log in
    with app.app_context():
        if not User.query.filter_by(username="admin").first():
            logging.warning("Creating default data.")
            demo_source1 = DataSource(
                import_name="manual",
                is_enabled=True,
                name="Demo Experiment 1",
                source_username="root",
                source_host="localhost",
                source_port="22",
                source_dir="/tmp/demo1",
                data_size="123",
            )
            demo_source2 = DataSource(
                import_name="manual",
                is_enabled=True,
                name="Demo Experiment 2",
                source_username="root",
                source_host="localhost",
                source_port="22",
                source_dir="/tmp/demo2",
                data_size="321",
            )
            demo_source3 = DataSource(
                import_name="manual",
                is_enabled=True,
                name="Demo Experiment 3",
                source_username="root",
                source_host="localhost",
                source_port="22",
                source_dir="/tmp/demo3",
                data_size="432",
            )

            localtester_group = Group(name="Local test users", is_public=True)
            stfctester_group = Group(name="STFC Cloud test users", is_public=True)
            imperialtester_group = Group(
                name="Imperial Cloud test users", is_public=True
            )

            admin_user = User(
                is_enabled=True,
                username="admin",
                given_name="Admin",
                family_name="Admin",
                group=localtester_group,
                language="en",
                is_admin=True,
                email="denis.volk@stfc.ac.uk",
                data_sources=[demo_source1, demo_source2],
            )
            admin_password = gen_token(8)
            admin_user.set_password(admin_password)

            stfctester_user = User(
                is_enabled=True,
                username="stfctester",
                given_name="NoName",
                family_name="NoFamilyName",
                group=stfctester_group,
                language="en",
                is_admin=False,
                email="noname@example.com",
                data_sources=[demo_source2, demo_source3],
            )
            stfctester_user_password = gen_token(8)
            stfctester_user.set_password(stfctester_user_password)

            imperialtester_user = User(
                is_enabled=True,
                username="imperialtester",
                given_name="NoName",
                family_name="NoFamilyName",
                group=imperialtester_group,
                language="en",
                is_admin=False,
                email="imperium@example.com",
                data_sources=[demo_source2, demo_source3],
            )
            imperialtester_user_password = gen_token(8)
            imperialtester_user.set_password(imperialtester_user_password)

            localtester_user = User(
                is_enabled=False,
                username="localtester",
                given_name="NoName",
                family_name="NoFamilyName",
                group=localtester_group,
                language="en",
                is_admin=False,
                email="local@example.com",
                data_sources=[demo_source2, demo_source3],
            )
            localtester_user_password = gen_token(8)
            localtester_user.set_password(localtester_user_password)

            notactivated1_user = User(
                username="notactivated1",
                given_name="NoName",
                family_name="NoFamilyName",
                language="en",
                email="local1@example.com",
            )
            notactivated1_user_password = gen_token(8)
            notactivated1_user.set_password(notactivated1_user_password)

            notactivated2_user = User(
                username="notactivated2",
                given_name="NoName",
                family_name="NoFamilyName",
                language="en",
                email="local2@example.com",
            )
            notactivated2_user_password = gen_token(8)
            notactivated2_user.set_password(notactivated2_user_password)

            logging.info(f"Created user: username: admin password: {admin_password}")
            logging.info(
                f"Created user: username: stfctester password: {stfctester_user_password}"
            )
            logging.info(
                f"Created user: username: imperialtester password: {imperialtester_user_password}"
            )
            logging.info(
                f"Created user: username: localtester password: {localtester_user_password}"
            )

            docker_machine_provider = MachineProvider(
                name="Local docker",
                type="docker",
                customer="",
                provider_data={
                    "base_url": "unix:///var/run/docker.sock",
                    "network": "adanet",
                },
            )
            libvirt_machine_provider = MachineProvider(
                name="Local libvirt",
                type="libvirt",
                customer="",
                provider_data={
                    "base_url": "qemu:///system",
                },
            )
            stfc_os_machine_provider = MachineProvider(
                name="STFC OpenStack",
                type="openstack",
                customer="IDAaaS-Dev",
                provider_data={
                    # TODO add provider core, mem, hdd limits
                    # and enforcement in /new_machine
                    "auth_url": "https://openstack.stfc.ac.uk:5000/v3",
                    "user_domain_name": "stfc",
                    "project_domain_name": "Default",
                    "username": "gek25866",
                    "password": "",
                    "project_name": "IDAaaS-Dev",
                },
            )
            imperial_os_machine_provider = MachineProvider(
                name="Imperial OpenStack",
                type="openstack",
                customer="daaas",
                provider_data={
                    "auth_url": "https://oskeystone.grid.hep.ph.ic.ac.uk:5000/v3/",
                    "user_domain_name": "Default",
                    "project_domain_name": "default",
                    "username": "fyangturner",
                    "password": "",
                    "project_name": "daaas",
                },
            )
            software_1 = Software(name="Ubuntu 20.04")
            software_2 = Software(name="Ubuntu 22.04")
            software_3 = Software(name="Debian 11")
            software_4 = Software(name="emacs 28.2")
            software_5 = Software(name="CUDA 11.8")

            docker_workspace_image = Image(
                name="workspace",
                machine_providers=[docker_machine_provider],
                softwares=[software_3, software_4, software_5],
            )
            libvirt_debian_image = Image(
                name="debian11-5",
                machine_providers=[libvirt_machine_provider],
                softwares=[software_3],
            )
            denis_dev_20230511 = Image(
                name="denis_dev_20230511",
                machine_providers=[stfc_os_machine_provider],
                softwares=[software_1],
            )
            rfi_demo_20230517 = Image(
                name="rfi_demo_20230517",
                machine_providers=[stfc_os_machine_provider],
                softwares=[software_1],
            )
            denis_dev_20230522 = Image(
                name="denis_dev_20230522",
                machine_providers=[imperial_os_machine_provider],
                softwares=[software_2],
            )

            # docker test
            test_machine_template1 = MachineTemplate(
                name="Docker bare demo",
                type="docker",
                memory_limit_gb=16,
                cpu_limit_cores=4,
                image=docker_workspace_image,
                os_username="ubuntu",
                group=localtester_group,
                machine_provider=docker_machine_provider,
                description="This is a docker machine template. It has a desktop but no special software installed. This is meant for development on a local pc.",
                extra_data={
                    "quota": 2,
                },
            )

            # libvirt test
            test_machine_template2 = MachineTemplate(
                name="Libvirt bare demo",
                type="libvirt",
                memory_limit_gb=16,
                cpu_limit_cores=4,
                disk_size_gb=20,
                image=libvirt_debian_image,
                os_username="ubuntu",
                group=localtester_group,
                machine_provider=libvirt_machine_provider,
                description="This is a libvirt machine template. It has a desktop but no special software installed. This is meant for development on a local pc.",
                extra_data={
                    "quota": 3,
                },
            )

            # stfc base image test
            test_machine_template3 = MachineTemplate(
                name="STFC bare demo",
                type="openstack",
                memory_limit_gb=32,
                disk_size_gb=200,
                cpu_limit_cores=8,
                image=denis_dev_20230511,
                os_username="ubuntu",
                group=stfctester_group,
                machine_provider=stfc_os_machine_provider,
                description="This is a STFC openstack template. It has a desktop but no special software installed. ",
                extra_data={
                    "flavor_name": "l3.tiny",
                    "network_uuid": "5be315b7-7ebd-4254-97fe-18c1df501538",
                    "vol_size": None,
                    "has_https": True,
                    "security_groups": [
                        {"name": "HTTP"},
                        {"name": "HTTPS"},
                        {"name": "SSH"},
                    ],
                    "quota": 4,
                },
            )

            # stfc rfi case test
            test_machine_template4 = MachineTemplate(
                name="STFC RFI demo",
                type="openstack",
                memory_limit_gb=32,
                cpu_limit_cores=8,
                disk_size_gb=200,
                image=rfi_demo_20230517,
                os_username="ubuntu",
                group=stfctester_group,
                machine_provider=stfc_os_machine_provider,
                description="RFI demo is a prototype image that includes Fiji (with plugins TrackEM2, SIFT, BDV, MoBIE), Ilastik, napari, ICY (ec-CLEM) and MIB",
                extra_data={
                    "flavor_name": "l3.tiny",
                    "network_uuid": "5be315b7-7ebd-4254-97fe-18c1df501538",
                    "vol_size": None,
                    "has_https": True,
                    "security_groups": [
                        {"name": "HTTP"},
                        {"name": "HTTPS"},
                        {"name": "SSH"},
                    ],
                    "quota": 4,
                },
            )

            # stfc rfi gpu case test
            test_machine_template5 = MachineTemplate(
                name="STFC RFI GPU demo",
                type="openstack",
                memory_limit_gb=90,
                cpu_limit_cores=12,
                disk_size_gb=700,
                image=rfi_demo_20230517,
                os_username="ubuntu",
                group=stfctester_group,
                machine_provider=stfc_os_machine_provider,
                description="RFI GPU demo is a prototype image that includes Fiji (with plugins TrackEM2, SIFT, BDV, MoBIE), Ilastik, napari, ICY (ec-CLEM) and MIB. This template has a nvidia GPU",
                extra_data={
                    "flavor_name": "g-rtx4000.x1",
                    "network_uuid": "5be315b7-7ebd-4254-97fe-18c1df501538",
                    "vol_size": None,
                    "has_https": True,
                    "security_groups": [
                        {"name": "HTTP"},
                        {"name": "HTTPS"},
                        {"name": "SSH"},
                    ],
                    "quota": 4,
                },
            )

            # imperial base image test
            test_machine_template6 = MachineTemplate(
                name="Imperial bare demo",
                type="openstack",
                memory_limit_gb=64,
                disk_size_gb=400,
                cpu_limit_cores=16,
                image=denis_dev_20230522,
                os_username="ubuntu",
                group=imperialtester_group,
                machine_provider=imperial_os_machine_provider,
                description="This is a Imperial openstack demo. It has a desktop but no special software installed.",
                extra_data={
                    "assign_floating_ip": True,
                    "hostname_postfix": ".machine.ada.oxfordfun.com",
                    "has_https": True,
                    "flavor_name": "daaas.xsmall",
                    "network_uuid": "91d10ac1-989c-42d0-a67f-e64dd6c04dc3",
                    "security_groups": [
                        {"name": "DAaaS_DMZ_policy_custom"},
                    ],
                    "quota": 4,
                },
            )

            db.session.add(admin_user)
            db.session.add(stfctester_group)
            db.session.add(stfctester_user)
            db.session.add(localtester_group)
            db.session.add(localtester_user)
            db.session.add(notactivated1_user)
            db.session.add(notactivated2_user)
            db.session.add(docker_machine_provider)
            db.session.add(libvirt_machine_provider)
            db.session.add(stfc_os_machine_provider)
            db.session.add(test_machine_template1)
            db.session.add(test_machine_template2)
            db.session.add(test_machine_template3)
            db.session.add(test_machine_template4)
            db.session.add(test_machine_template5)
            db.session.add(test_machine_template6)
            db.session.commit()


def clean_up_db():
    """
    Because threads are used for background tasks, anything that
    was running when the application closed will be interrupted.

    This function sets any database entries that were running into
    a failed state.

    We could also try to recover or restart some things.
    """
    with app.app_context():
        for m in Machine.query.all():
            if m.state == MachineState.PROVISIONING:
                logging.warning(f"Setting machine {m.name} to FAILED state")
                m.state = MachineState.FAILED
                # TODO: make sure all machine resources are deleted
        for j in DataTransferJob.query.all():
            if j.state == DataTransferJobState.RUNNING:
                logging.warning(f"Setting DataTransferJob {j.id} to FAILED state")
                j.state = DataTransferJobState.FAILED
                # Could also restart?
        db.session.commit()


def is_next_uri_share_accept(endpoint):
    is_share_accept_link = False
    if endpoint == None:
        pass
    elif len(re.findall(r"^share_accept/[A-Za-z0-9]{16}$", endpoint[1:])) == 1:
        is_share_accept_link = True
    return is_share_accept_link


def email_forgot_password_link(site_root, login_link, user_id):
    with app.app_context():
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return

        email_to = user.email
        logging.info(f"Sending password forgot email to: {email_to}")
        msg = Message(
            "Ada Data Analysis forgotten password",
            sender=MAIL_SENDER,
            recipients=[email_to],
        )
        msg.body = f"""Hi,

We have received a request to reset your password for your account associated with this email address.

If you made this request, please click on the link below to log in. If you didn't make this request, please ignore this email.

{login_link}

For your security, we recommend that you choose a unique password that you don't use on other websites or services.
"""
        mail.send(msg)
        logging.info(f"Emailed {email_to} an email login link")

@app.route("/send_test_email", methods=["POST"])
@login_required
@profile_complete_required
def send_test_email():
    def send(msg):
        with app.app_context():
            mail.send(msg)

    audit = create_audit("test email")
    email_to = current_user.email
    logging.info(f"Sending test email to: {email_to}")
    if not current_user.is_admin:
        logging.info("Current user not admin - won't send test email.")
        finish_audit(audit, state="failed")
        return redirect("/")
    msg = Message(
        "Ada Data Analysis test email",
        sender=MAIL_SENDER,
        recipients=[email_to],
    )
    msg.body = f"""Hi,

You have recieved this email because you requested a test email from Ada Data Analysis ({request.url_root}).
"""
    threading.Thread(
        target=send, args=(msg,)
    ).start()
    logging.info(f"Emailed {email_to} a test message")
    finish_audit(audit, state="ok")
    return redirect(url_for("admin"))

def determine_redirect(share_accept_token_in_session):
    """
    determines where a user should be redirected to upon login based on if there is a share token in the URL

    if there is then we use the share token to add the machine to their list of machines

    otherwise, just send them to the welcome page
    """
    resp = redirect(url_for("welcome"))
    if share_accept_token_in_session:
        try:
            resp = redirect(
                url_for(
                    "share_accept", machine_share_token=share_accept_token_in_session
                )
            )
        except:
            pass
        session.pop("share_accept_token")
    return resp


def init_user_keys(user_id):
    """Create a ssh key for a user."""
    user = User.query.filter_by(id=user_id).first()
    logging.info(f"generating keys for user {user.id}")
    private_key, public_key = keys.generate_user_keys(str(user.id))
    user.ssh_keys = gen_ssh_keys(user_id)
    db.session.commit()


def init_deploy_user_keys(user_id):
    """Deploy a user's keys to their existing machines."""
    user = User.query.filter_by(id=user_id).first()
    for machine in Machine.query.filter_by(state=MachineState.READY, owner_id=user.id):
        try:
            logging.info(f"deploying keys for user {user.id} to {machine.ip}")
            keys.deploy_user_keys_to_machine(
                machine.ip,
                user.ssh_keys.private_key,
                user.ssh_keys.public_key,
                user.ssh_keys.authorized_keys,
            )
        except Exception as e:
            logging.warning(
                f"couldn't dpeloy key for {user.id} to {machine.ip}: {str(e)}"
            )


def init_users_keys():
    """On program start, generate missing keys and deploy to machines."""
    with app.app_context():
        for user in User.query.all():
            if not user.ssh_keys:
                init_user_keys(user.id)
                init_deploy_user_keys(user.id)


def main(debug=False):
    with app.app_context():
        create_audit("app", state="started")

    create_initial_db()
    clean_up_db()
    # init_users_keys()

    VirtService.set_app(app)

    if debug:
        app.run(debug=True)
    else:
        waitress.serve(app, host="0.0.0.0", port=5000)


if __name__ == "__main__":
    argh.dispatch_command(main)
