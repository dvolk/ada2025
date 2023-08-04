import argh


def os_go():
    import app

    with app.app.app_context():
        mps = app.MachineProvider.query.all()
        app.OpenStackService.build_image(mps[2])


if __name__ == "__main__":
    argh.dispatch_command(os_go)
