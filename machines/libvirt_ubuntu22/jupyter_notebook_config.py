c = get_config()  # noqa

# serve jupyter on /jupyter/ not /
c.NotebookApp.base_project_url = "/jupyter/"

# set default dir
c.NotebookApp.notebook_dir = "/home/ubuntu/notebooks"

# we're using nginx to proxy to notebook
c.NotebookApp.allow_remote_access = True

# we're running in systemd - don't open browser
c.NotebookApp.open_browser = False

# disable authentication as we're using an authentication proxy
c.NotebookApp.password = ""
c.NotebookApp.token = ""
