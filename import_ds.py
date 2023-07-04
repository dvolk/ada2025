"""Import data sources from csv into Ada.

Data sources define the external data that users can copy into their
virtual machines. They are stored in a table, and here we import it
from a csv, giving users the ability to define data sources externally
that we then fetch periodically.

Note that because read_csv() supports urls, you can pass in urls here

Usage example:

python3 import_ds.py /path/to/your/data.csv
python3 import_ds.py https://example.com/your/data.csv

Example csv:

ImportName,SourceName,SourceUsername,SourceHost,SourcePort,SourceDir,DataSize,AccessUser
Group1,Experiment 1,root,site1.com,22,/mnt/data/experiments/exp1,2000MB,denis.volk@stfc.ac.uk
Group1,Experiment 1,root,site1.com,22,/mnt/data/experiments/exp1,2000MB,noname@example.com
Group1,Experiment 2,root,site1.com,22,/mnt/data/experiments/exp2,2000MB,noname@example.com
Group1,Experiment 3,root,site2.com,22,/mnt/data/experiments/exp3,3000MB,denis.volk@stfc.ac.uk
Group1,Experiment 3,root,site2.com,22,/mnt/data/experiments/exp3,3000MB,noname@example.com
Group2,Experiment 6,root,site2.com,22,/mnt/data/experiments/exp3,3000MB,denis.volk@stfc.ac.uk
Group2,Experiment 6,root,site2.com,22,/mnt/data/experiments/exp3,3000MB,noname@example.com

ImportName identifies the data source... source.
it must be globally unique, and there should really be one per csv

All the columns for a given experiment must be unique other than AccessUser. This is enforced
by validate_csv
"""

import sys
import logging

import pandas as pd
from sqlalchemy import and_

from app import app, db, DataSource, User


def validate_csv(df):
    # Get all columns except 'SourceName' and 'AccessUser'
    columns_to_check = [
        col for col in df.columns if col not in ["SourceName", "AccessUser"]
    ]

    # Group the dataframe by 'SourceName' and apply nunique() function only on the required columns
    grouped = df.groupby("SourceName")[columns_to_check].nunique()

    # List to store all inconsistencies
    inconsistencies = []

    # Check if any of the grouped DataFrame's columns have a value larger than 1
    # which would indicate that there are multiple unique values within a group
    for column in grouped.columns:
        # Get indexes (SourceName values) where count > 1
        inconsistent_sources = grouped[grouped[column] > 1].index.tolist()
        if inconsistent_sources:
            inconsistencies.append(
                f"Error: Rows with the same SourceName have different {column} values for: {', '.join(inconsistent_sources)}"
            )

    # If any inconsistencies were found, print them and return False
    if inconsistencies:
        for error in inconsistencies:
            logging.warning(error)
        return False

    return True


def sync_data_source_with_csv(csv_filepath):
    # Read CSV file
    df = pd.read_csv(
        csv_filepath,
        storage_options={"verify": False},  # don't validate certs. Thanks fortigate
    )

    if not validate_csv(df):
        logging.error(f"Couldn't validate csv: {csv_filepath}")

    # Group the dataframe by SourceName and convert the AccessUser values to lists
    grouped = df.groupby("SourceName")["AccessUser"].apply(list).to_dict()

    # Open a new session
    with app.app_context():
        for index, row in df.iterrows():
            # Find the user
            user = (
                db.session.query(User).filter(User.email == row["AccessUser"]).first()
            )

            # If the user does not exist, continue to the next row
            if user is None:
                continue

            # Find existing data source
            data_source = (
                db.session.query(DataSource)
                .filter(
                    and_(
                        DataSource.name == row["SourceName"],
                        DataSource.import_name == row["ImportName"],
                    )
                )
                .first()
            )

            # Convert DataSize to integer (MB)
            data_size = int(row["DataSize"].replace("MB", ""))

            # If the data source does not exist, create a new one
            if data_source is None:
                data_source = DataSource(
                    import_name=row["ImportName"],
                    name=row["SourceName"],
                    source_username=row["SourceUsername"],
                    source_host=row["SourceHost"],
                    source_port=row["SourcePort"],
                    source_dir=row["SourceDir"],
                    data_size=data_size,
                )
                db.session.add(data_source)

            # If user not in data source users, add
            if user not in data_source.users:
                data_source.users.append(user)

        # Commit the session to add/update the data sources to the database
        db.session.commit()

        # Remove users from the data sources that do not exist in the CSV for the respective DataSource
        for data_source in db.session.query(DataSource).all():
            if data_source.name in grouped:
                csv_users_emails = grouped[data_source.name]
                for user in data_source.users:
                    if user.email not in csv_users_emails:
                        data_source.users.remove(user)
            else:
                # If DataSource not in CSV, remove all users
                data_source.users = []

        # Commit the session to remove the users from the data sources
        db.session.commit()


def main():
    import_file = sys.argv[1]
    print(f"Importing from {import_file}")
    sync_data_source_with_csv(import_file)


if __name__ == "__main__":
    main()
