"""
Delete machines belonging to group that are too old.


"""

import logging
from datetime import datetime, timedelta
import threading

import argh

from app import (
    app,
    Machine,
    MachineState,
    MachineTemplate,
    User,
    db,
    and_,
    VirtService,
    DockerService,
    OpenStackService,
    Audit,
    create_audit,
    update_audit,
    finish_audit,
)


def main(group_id, hours_old_to_delete, do_delete=False):
    """
    Delete machines belonging to group that are too old.
    """
    with app.app_context():
        VirtService.set_app(app)

        current_time = datetime.utcnow()
        time_hours_ago = current_time - timedelta(hours=int(hours_old_to_delete))

        # get machines from group that are > hours old
        results = (
            db.session.query(User, Machine, MachineTemplate)
            .join(Machine, Machine.owner_id == User.id)
            .join(MachineTemplate, Machine.machine_template_id == MachineTemplate.id)
            .filter(
                and_(
                    MachineTemplate.group_id == group_id,
                    Machine.state.in_([MachineState.READY, MachineState.STOPPED]),
                    Machine.creation_date <= time_hours_ago,
                    ~User.is_admin,
                )
            )
        ).all()

        for u, m, mt in results:
            machine_age = current_time - m.creation_date
            print(
                f"template: {mt.name}, owner: {u.username}, name: {m.display_name}, age: {machine_age}"
            )
            if do_delete:
                audit = create_audit("timeout vm", "starting")
                update_audit(audit, machine=m)
                OpenStackService.stop(m.id, audit.id)
                finish_audit(audit, "ok")


if __name__ == "__main__":
    argh.dispatch_command(main)
