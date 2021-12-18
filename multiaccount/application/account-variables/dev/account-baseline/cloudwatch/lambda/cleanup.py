import boto3
from datetime import datetime, timedelta

client = boto3.client('logs')

# Entry function for lambda
def handler(event, context):

    response = client.describe_log_groups()
    # Do while there is still a nextToken
    while True:
        # Check each Log Group
        for group in response["logGroups"]:
            # If the rentention policy is set, logs will expire at some point need to check the log groups
            if "retentionInDays" in group:
                check_group_streams(group["logGroupName"], group["retentionInDays"])
        # Exit if no more to parse
        if "nextToken" not in response:
            break
        # Get next batch if there is a nextToken
        else:
            response = client.describe_log_groups(nextToken=response['nextToken'])

# Function that takes the Log Group and Expiration in days to check each stream
def check_group_streams(name, days):
    print("Checking... " + name + " " + str(days))

    # Create datetime object for the expiration time
    threshold = datetime.now() - timedelta(days=days)

    response = client.describe_log_streams(
        logGroupName=name,
        orderBy='LastEventTime',
        descending=False
    )
    # Emulate do while to work through all log streams
    while True:
        for stream in response['logStreams']:
            # Remove last 3 digits from timestamp (milliseconds not compatable with datetime) and create
            # Datetime object to compare to the threshold
            if 'lastEventTimestamp' in stream:
                last_event = datetime.fromtimestamp(int(str(stream['lastEventTimestamp'])[:-3]))
                # If the last event is older than the threshold, remove it
                if last_event < threshold:
                    print("Deleting: " + name + " " + stream['logStreamName'] + " " + str(last_event))
                    delete_response = client.delete_log_stream(
                        logGroupName=name,
                        logStreamName=stream['logStreamName']
                    )
                    print(delete_response)
            else:
                print(stream['logStreamName'] + ": No events detected, deleting")
                delete_response = client.delete_log_stream(
                    logGroupName=name,
                    logStreamName=stream['logStreamName']
                )
                print(delete_response)

        # Get next batch if necessary
        if "nextToken" not in response:
            break
        else:
            response = response = client.describe_log_streams(
                logGroupName=name,
                orderBy='LastEventTime',
                descending=False,
                nextToken=response['nextToken']
            )
