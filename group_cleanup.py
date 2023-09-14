"""
Delete machines belonging to group that are too old.


"""

import logging
from datetime import datetime, timedelta

import argh

from app import (
    app,
    Machine,
    MachineState,
    MachineTemplate,
    db,
    and_,
    OpenStackService,
    Audit,
    create_audit,
    finish_audit,
)


def main(group_id, hours_old_to_delete, do_delete=False):
    """
    Delete machines belonging to group that are too old.
    """
    with app.app_context():
        current_time = datetime.utcnow()
        time_hours_ago = current_time - timedelta(hours=int(hours_old_to_delete))

        # get machines from group that are > hours old
        results = (
            db.session.query(Machine, MachineTemplate)
            .join(MachineTemplate, Machine.machine_template_id == MachineTemplate.id)
            .filter(
                and_(
                    MachineTemplate.group_id == group_id,
                    Machine.state.in_([MachineState.READY, MachineState.STOPPED]),
                    Machine.creation_date <= time_hours_ago,
                )
            )
        ).all()

        # delete expired machines
        for result in results:
            if not do_delete:
                m = result[0]
                mt = result[1]
                print(f"{mt.name},{m.display_name},{m.creation_date},{m.state}")

            if do_delete:
                audit = create_audit("timeout vm", "starting")
                OpenStackService.stop(m.id, 0)
                finish_audit(audit, "ok")


if __name__ == "__main__":
    argh.dispatch_command(main)
