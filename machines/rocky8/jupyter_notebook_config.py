c = get_config()  # noqa

# serve jupyter notebook on /jupyter-notebook/ not /
c.ServerApp.base_url = "/jupyter-notebook/"

# set default dir
c.ServerApp.notebook_dir = "/home/ubuntu/notebooks"

# we're using nginx to proxy to notebook
c.ServerApp.allow_remote_access = True

# we're running in systemd - don't open browser
c.ServerApp.open_browser = False

# disable authentication as we're using an authentication proxy
c.ServerApp.password = ""
c.ServerApp.token = ""

# prevent bug with xsrf cookie
c.ServerApp.disable_check_xsrf = True
