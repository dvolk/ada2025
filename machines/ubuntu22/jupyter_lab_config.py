c = get_config()  # noqa

# serve jupyter lab on /jupyter-lab/ not /
c.ServerApp.base_url = "/jupyter-lab/"

# set default dir
c.ServerApp.root_dir = "/home/ubuntu/notebooks"

# we're using nginx to proxy to jupyter lab
c.ServerApp.allow_remote_access = True

# we're running in systemd - don't open browser
c.ServerApp.open_browser = False

# disable authentication as we're using an authentication proxy
c.ServerApp.password = ""
c.ServerApp.token = ""

# prevent bug with xsrf cookie
c.ServerApp.disable_check_xsrf = True

# set the port
c.ServerApp.port = 8889
