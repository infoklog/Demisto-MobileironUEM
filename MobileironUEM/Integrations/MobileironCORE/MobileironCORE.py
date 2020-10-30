import demistomock as demisto
from CommonServerPython import *
import json
import requests
import traceback
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

'''Constants'''

default_fields = "common.uuid,common.compliant,common.id,common.imei,common.imsi,common.last_connected_at,common.manufacturer,common.model,common.noncompliance_reasons,common.owner,common.platform,common.quarantined,common.quarantined_reasons,common.registration_date,common.status,user.display_name,user.email_address,user.user_id,common.security_state"
translation_core = {
    'common.uuid': 'deviceId',
    'common.id': 'Id',
    'common.os_version': 'OS Version',
    'common.manufacturer': 'manufacturer',
    'common.model': 'DeviceModel',
    'common.status': 'Registration Status',
    'common.imei': 'IMEI',
    'common.imsi': 'IMSI',
    'common.platform': 'Platform',
    'common.security_state': 'Security State',
    'user.display_name': 'User Display Name',
    'user.email_address': 'User Email address',
    'user.user_id': 'User ID',
    'common.last_connected_at': 'Last check in Timestamp',
    'common.registration_date': 'Device registration timestamp',
    'common.owner': 'Device Owner',
    'common.quarantined': 'IsDeviceQuarantined',
    'common.compliant': 'IsDeviceCompliant'
}

""" Read the integration params and declare them as global variables.
"""
params = demisto.params()
credentials = params.get('credentials')
username = credentials.get('identifier')
password = credentials.get('password')
base_url = params.get('url')
devices_url = urljoin(params.get('url'), '/api/v2/devices?')
post_action_url = urljoin(params.get('url'), '/api/v2/devices/action?')
admin_space_id = params.get('adminDeviceSpaceId')
additional_fields = params.get('additionalfields')
queryParam = params.get('query')
timeInteval = params.get('fetch_interval')

# Initiate default data for headers.
auth_header = b64_encode(f'{username}:{password}')
headers = {
    'Authorization': f'Basic {auth_header}'
}

incidents = []
translation = []


class MobileironClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get_devices_data(self, query: str = queryParam, fields: str = default_fields, adminspaceid: str = admin_space_id) -> Dict[str, Any]:
        """Gets the Devices Data from Mobileiron Core

        :type query: ``str``
        :param query: Conditions in the Core API Call

        :type fields: ``str``
        :param fields: Attributes to be retrieved

        :type adminspaceid: ``str``
        :param adminspaceid: Admin Space ID

        :return: dict containing Devices Data as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        if additional_fields:
            fields = fields + ',' + additional_fields
        """ Code for Pagination
            The core device api can retrive only limited list of devices at each run.
            fetchBatch is the attribute used to set the limit for each run. The default value is 25.
            This value can be changed according to the information provided in API documentation from Mobileiron Core.
        """
        fetchBatch = 2
        """ find the devices count. """
        response = self._http_request(
            method='GET',
            url_suffix='/api/v2/devices/count',
            params={
                'adminDeviceSpaceId': admin_space_id,
                'query': query,
                'fields': fields
            }
        )
        data = []
        cntDevices = response["totalCount"]
        inCnt = 0
        """ If the devices count is more than the fetchBatch(number of devices to fetch in each run)
            Loop through in batch mode and append the device data into data[] array.
        """

        if (int(cntDevices) > fetchBatch):
            while inCnt < cntDevices:
                # Get batch incidents from intCnt to inCnt+fetchBatch
                deviceResponse = self._http_request(
                    method='GET',
                    url_suffix='/api/v2/devices',
                    params={
                        'adminDeviceSpaceId': admin_space_id,
                        'query': query,
                        'fields': fields,
                        'limit': fetchBatch,
                        'offset': inCnt
                    }
                )
                for device in deviceResponse['results']:
                    data.append(device)
                inCnt += fetchBatch
        else:
            """ If the devices count is less than the fetchBatch(number of devices to fetch in each run)
                fetch all the devices in one run and append the device data into data[] array.
            """
            # Get full list of devices.
            deviceResponse = self._http_request(
                    method='GET',
                    url_suffix='/api/v2/devices',
                    params={
                        'adminDeviceSpaceId': admin_space_id,
                        'query': query,
                        'fields': fields
                    }
                )
            for device in deviceResponse['results']:
                data.append(device)
        """ return the value back to the fetch_incidents function.
        """
        return data

    def get_device_severity(self, deviceInfo: Dict[str, Any]) -> str:
        """Gets the severity based on following conditions

        :type deviceInfo: ``json``
        :param deviceInfo: Device Object with attributes info

        return : 'str'
        return param: returns severity to be set on the incident

        """

        """severity default value set to low"""
        severity = convert_to_demisto_severity('Low')

        if deviceInfo['common.security_state']:
            severity = convert_to_demisto_severity('Critical')
            return severity
        elif deviceInfo['common.complaint'] == False:
            severity = convert_to_demisto_severity('High')
            return severity
        elif deviceInfo['common.quarantined']:
            severity = convert_to_demisto_severity('Low')
            return severity

        return severity

    def execute_action(self, action_str: str, deviceid: str, method_type: str) -> Dict[str, Any]:
        """Execute Post actions to Mobileiron CORE based on the conditions.

        :type action_str: ``str``
        :param action_str: Action String based on the action to be performed over Mobileiron Core.
        :type deviceid: ``str``
        :param deviceid: DeviceID on which the actions should be performed..
        :type method_type: ``str``
        :param method_type: Method type for the actions to be performed ('PUT','POST','GET')

        :return: dict containing the scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        payload = {"deviceUuids": [deviceid], "note": "Action Performed through XSOAR-Integration"}
        action_url_str = ""
        if (action_str == "WIPE_DEVICE"):
            action_url_str = "wipe"
        elif (action_str == "RETIRE"):
            action_url_str = "retire"
        elif (action_str == "WAKE_UP"):
            action_url_str = "wakeup"
        else:
            action_url_str = "action"

        # Body = json.dumps(payload)
        return self._http_request(
            method=method_type,
            url_suffix='/api/v2/devices/' + action_url_str,
            params={
                'adminDeviceSpaceId': admin_space_id,
                'actionType': action_str
            },
            json_data=payload
        )

    def send_message(self, msg_str: str, msg_mode: str, msg_sub: str, deviceid: str) -> Dict[str, Any]:
        """Execute send message action to Mobileiron CORE based on the conditions.

        :type msg_str: ``str``
        :param msg_str: Message to send to the specified devices.
        :type msg_mode: ``str``
        :param msg_mode: Mode of the message:
                            • pns (push notifications)
                            • sms
                            • email (email takes the subject parameter, too)
        :type msg_sub: ``str``
        :param msg_sub: Provide if desired when the message mode is email.
        :type deviceid: ``str``
        :param deviceid: DeviceID on which the actions should be performed..


        :return: dict containing the scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        payload = {"deviceUuids": [deviceid], "note": "Message sent through XSOAR-Integration",
                   "additionalParameters": {"message": msg_str, "mode": msg_mode, "subject": msg_sub}}
        #Body = json.dumps(payload)
        return self._http_request(
            method='POST',
            url_suffix='/api/v2/devices/action',
            params={
                'adminDeviceSpaceId': admin_space_id,
                'actionType': 'SEND_MESSAGE'
            },
            json_data=payload
        )

    def ping_url(self):
        """Executes PING ´to check for the connection with Mobileiron CORE.

        :return: Demisto.results(ok)
        :rtype:
        """
        #payload = {"deviceUuids": [deviceid], "note": "Message sent through XSOAR-Integration", "additionalParameters":{"message":msg_str,"mode":msg_mode,"subject":msg_sub  }}
        #Body = json.dumps(payload)
        response = self._http_request(
            method='GET',
            url_suffix='/api/v2/ping'
        )
        if (response) and (response["results"]):
            demisto.results('ok')


def rename_keys(event_input: Dict[str, Any], keys: Dict[str, Any]) -> Dict[str, Any]:
    """ Function to rename/translate keys from the API Response

        :type event_input: ``str``
        :param event_input: Each device information retrieved from CORE.
        :type keys: ``str``
        :param keys: Translated keys set as definied in the headers.

        :return: dict containing the scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

    return dict([(keys.get(k, k), v) for k, v in event_input.items()])


def datetime_to_posix_without_milliseconds(datetime_object):
    """ Function to convert UTC time to string. """
    timestamp_in_unix_millisecond = date_to_timestamp(datetime_object, 'datetime.datetime')
    posix_with_ms = timestamp_in_unix_millisecond
    posix_without_ms = str(posix_with_ms).split(',')[0]
    return posix_without_ms


def convert_to_demisto_severity(severity: str) -> int:
    """Maps severity to Cortex XSOAR severity

    Converts the severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned based on device data input (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4   # critical severity
    }[severity]


def execute_command(client: MobileironClient, args: Dict[str, Any], action_str, method_type) -> CommandResults:
    """mobileiron-unlock-device-only command: Returns results for a Mobileiron PostAction

    :type client: ``Client``
    :param Client: Mobileiron client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['device_id']`` Device ID to post actions on a device

    :return:
        A ``CommandResults`` compatible to return ``return_results()``,
        that contains a Post action result
        A Dict of entries also compatible to ``return_results()``

    :rtype: ``CommandResults``
    """

    deviceid = args.get('device_id', None)
    action_str = action_str
    response = client.execute_action(action_str=action_str, deviceid=deviceid, method_type=method_type)

    validation = response["successful"]
    if validation:
        results = {'cmd_result': True,
                   'err_code': 0,
                   'err_message': 'Command has been executed sucessfully'
                   }

        return CommandResults(
            # readable_output=readable_output,
            outputs_prefix='Mobileiron',
            outputs_key_field='cmd_result',
            outputs=results
        )
    else:
        raise ValueError(response)


def ping_url(client: MobileironClient):
    """ This definition is for test command - get Ping response from Core


        :return: demisto.results('ok')
        :rtype: string.
        """
    version_url = urljoin(base_url, '/api/v2/ping')
    response = client.ping_url()


def fetch_incidents(client: MobileironClient) -> List[Dict[str, Any]]:
    """
        This function returns incidents after analyzing the response data

        This function has to implement the logic of making sure that incidents are
        fetched based on analyzing the response data. By default it's invoked by
        XSOAR every minute. It will use last_run to save the timestamp of the last
        incident it processed.

        :type client: ``Client``
        :param Client: Mobileiron Core client to use

        :return:
            incidents are returned in the form of dict
    """

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    """get the devices data from Core Call API response"""
    devices_response = client.get_devices_data()
    #devices = devices_response['results']

    for device in devices_response:

        # If no name is present it will throw an exception
        incident_name = device['common.model']

        # Rename keys for device attributes
        modified_device = rename_keys(device, translation_core)

        # get Device Severity
        severity = client.get_device_severity(device)

        # INTEGRATION DEVELOPER TIP
        # The incident dict is initialized with a few mandatory fields:
        # name: the incident name
        # rawJSON: everything else is packed in a string via json.dumps()
        # and is included in rawJSON. It will be used later for classification
        # and mapping inside XSOAR.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSOAR specific severity (int 1 to 4)
        # Type : Incident Type
        incident = {
            'name': incident_name,
            'rawJSON': json.dumps(modified_device),
            'type': 'UEM Device Core',  # Map to a specific XSOAR incident Type
            'severity': severity
        }
        incidents.append(incident)

    return incidents


def get_devices_data_command(client: MobileironClient, args: Dict[str, Any]) -> CommandResults:
    """get-devices command: Returns a list of all devices in the mobileiron system

    :type client: ``MobileironClient``
    :param client: Mobileiron UEM client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the device data

    :rtype: ``CommandResults``
    """

    devices_data_response = client.get_devices_data()
    #devices_data = devices_data_response['results']
    #readable_output = tableToMarkdown(f'Device List', devices_data)

    return CommandResults(
        # readable_output=readable_output,
        outputs_prefix='Mobileiron.DevicesInfo',
        outputs_key_field='devices_data',
        outputs=devices_data_response
    )


def send_message_command(client: MobileironClient, args: Dict[str, Any]) -> CommandResults:
    """mobileiron-update-os command: Returns results for a Mobileiron PostAction

    :type client: ``Client``
    :param Client: Mobileiron client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['device_id']`` Device ID to post actions on a device

    :return:
        A ``CommandResults`` compatible to return ``return_results()``,
        that contains a Post action result
        A Dict of entries also compatible to ``return_results()``

    :rtype: ``CommandResults``
    """

    deviceid = args.get('device_id', None)
    message = args.get('message', None)
    subject = args.get('subject', None)
    puschMsg = args.get('push_message', None)

    response = client.send_message(message, puschMsg, subject, deviceid)
    validation = response["successful"]
    if validation:
        results = {'cmd_result': True,
                   'err_code': 0,
                   'err_message': 'Command has been executed sucessfully'
                   }

        return CommandResults(
            # readable_output=readable_output,
            outputs_prefix='Mobileiron',
            outputs_key_field='cmd_result',
            outputs=results
        )
    else:
        raise ValueError(response)


def main():

    # if your MobileironClient class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the MobileironClient constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your MobileironClient class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the MobileironClient constructor
    proxy = demisto.params().get('proxy', False)
    try:

        client = MobileironClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            ping_url(client)

        elif demisto.command() == 'fetch-incidents':
            # Code For changing the pull incidents with timeline.
            now_utc = datetime.utcnow()
            current_run_time_posfix = datetime_to_posix_without_milliseconds(now_utc)
            current_run_time = current_run_time_posfix

            last_run_data = demisto.getLastRun()
            last_run_time = int(0)
            if last_run_data:
                last_run_time = last_run_data['time']

            next_run_interval = timeInteval
            date_time_interval_ago = now_utc - timedelta(minutes=int(next_run_interval))
            date_time_interval_ago_posix = datetime_to_posix_without_milliseconds(date_time_interval_ago)
            time_interval_ago = date_time_interval_ago_posix

            if last_run_time != 0:
                if last_run_time > time_interval_ago:
                    noIncidents = []
                    demisto.incidents(noIncidents)
                    sys.exit(0)
                    # End of skip based on the time interval.

            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents = fetch_incidents(
                client=client
            )
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to crate
            demisto.incidents(incidents)
            demisto.setLastRun({'time': current_run_time})

        elif demisto.command() == 'mobileiron-get-devices-data':
            # To get the list of devices data with the given parameters.
            return_results(get_devices_data_command(client, demisto.args()))

        elif demisto.command() == 'mobileiron-unlock-device-only':
            # Post Action to unclock a Fetched device based on device id
            #return_results(unlock_device_only_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "UNLOCK_DEVICE_ONLY", "POST"))

        elif demisto.command() == 'mobileiron-enable-voice-roaming':
            # Post Action to enable voice roaming on a Fetched device based on device id
            #return_results(enable_voice_roaming_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "ENABLE_VOICE_ROAMING", "POST"))

        elif demisto.command() == 'mobileiron-disable-voice-roaming':
            # Post Action to disable voice roaming on a Fetched device based on device id
            # return_results(disable_voice_roaming_command(client, demisto.args()))DISABLE_VOICE_ROAMING
            return_results(execute_command(client, demisto.args(), "DISABLE_VOICE_ROAMING", "POST"))

        elif demisto.command() == 'mobileiron-enable-data-roaming':
            # Post Action to enable data roaming on a Fetched device based on device id
            #return_results(enable_data_roaming_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "ENABLE_DATA_ROAMING", "POST"))

        elif demisto.command() == 'mobileiron-disable-data-roaming':
            # Post Action to disable data roaming on a Fetched device based on device id
            #return_results(disable_data_roaming_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "DISABLE_DATA_ROAMING", "POST"))

        elif demisto.command() == 'mobileiron-enable-personal-hotspot':
            # Post Action to enable personal hotspot on a Fetched device based on device id
            #return_results(enable_personal_hotspot_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "ENABLE_PERSONAL_HOTSPOT", "POST"))

        elif demisto.command() == 'mobileiron-disable-personal-hotspot':
            # Post Action to disable personal hotspot on a Fetched device based on device id
            #return_results(disable_personal_hotspot_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "DISABLE_PERSONAL_HOTSPOT", "POST"))

        elif demisto.command() == 'mobileiron-send-message':
            # Post Action to send message on a Fetched device based on device id
            return_results(send_message_command(client, demisto.args()))

        elif demisto.command() == 'mobileiron-update-os':
            # Post Action to update OS on a Fetched device based on device id
            #return_results(update_os_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "UPDATE_OS", "POST"))

        elif demisto.command() == 'mobileiron-unlock-app-connect-container':
            # Post Action to unlock app container on a Fetched device based on device id
            #return_results(unlock_app_connect_container_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "UNLOCK_APP_CONNECT_CONTAINER", "POST"))

        elif demisto.command() == 'mobileiron-retire-device':
            # Post Action to retire a device on a Fetched device based on device id
            #return_results(retire_device_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "RETIRE", "PUT"))

        elif demisto.command() == 'mobileiron-wipe-device':
            # Post Action to wipe a device on a Fetched device based on device id
            #return_results(wipe_device_command(client, demisto.args()))
            return_results(execute_command(client, demisto.args(), "WIPE_DEVICE", "PUT"))

        elif demisto.command() == 'mobileiron-force-checkin':
            # Post Action to force-checkin a device on a Fetched device based on device id
            return_results(execute_command(client, demisto.args(), "WAKE_UP", "PUT"))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
