import json
import requests
import traceback
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

'''Constants'''

""" Transaltion of KEY names which are retreived from response (Cloud) are defined in translation_cloud
    ** Add using comma separated values to translation_cloud
    Example --- ,'imei':'IMEI'
"""
translation_cloud = {
                        'guid':'Id',
                        'id':'deviceId',
                        'platformVersion':'OS Version',
                        'manufacturer':'manufacturer',
                        'deviceModel':'DeviceModel',
                        'registrationState':'registration Status',
                        'imei':'IMEI',
                        'imsi':'IMSI',
                        'platformType':'Platform',
                        'jailbroken':'Security State',
                        'displayName':'User Display Name',
                        'emailAddress':'User Email address',
                        'uid':'User ID',
                        'clientLastCheckin':'Last check in Timestamp',
                        'lastRegistrationTime':'Device registration timestamp',
                        'ownershipType':'DeviceOwner',
                        'quarantined':'IsDeviceQuarantined',
                        'complianceState':'IsDeviceCompliant'}

""" Read the integration params and declare them as global variables.
"""

params = demisto.params()
credentials = params.get('credentials')
username = credentials.get('identifier')
password = credentials.get('password')
base_url = params.get('url')
dm_partition_id = params.get('dmPartitionId')
queryParam = params.get('query')
timeInteval = params.get('fetch_interval')


#Initiate default data for headers.
auth_header = b64_encode(f'{username}:{password}')
headers = {
    'Authorization': f'Basic {auth_header}'
}


incidents = []
translation = []

class MobileironClient(BaseClient):
    """MobileironClient class to interact with the service API

    This MobileironClient implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get_devices_data(self, query: str = queryParam , dmpartitionid: str = dm_partition_id ) -> Dict[str, Any]:
        """
        Function to get response by building an API through user input and returning
        all the devices list with required information and conditions using query
        type query: String
        dmpartitionid: String

        Returns - Response data in the form of Dict

        """

        """ Code for Pagination
            The core device api can retrive only limited list of devices at each run.
            fetchBatch is the attribute used to set the limit for each run. The default value is 25.
            This value can be changed according to the information provided in API documentation from Mobileiron Core.

        """

        fetchBatch = 2
        """ find the devices count. """
        data = []
        response = self._http_request(
                method='GET',
                url_suffix='/api/v1/device',
                params={
                    'dmPartitionId':dm_partition_id,
                    'fq':query
                }
            )
        results = response['result']
        cntDevices = results['totalCount']
        inCnt = 0
        """ If the devices count is more than the fetchBatch(number of devices to fetch in each run)
            Loop through in batch mode and append the device data into data[] array.
        """

        if (int(cntDevices) > fetchBatch):
            while inCnt < cntDevices:
                #Get batch incidents from intCnt to inCnt+fetchBatch
                deviceResponse = self._http_request(
                        method='GET',
                        url_suffix='/api/v1/device',
                        params={
                            'dmPartitionId':dm_partition_id,
                            'fq':query,
                            'rows':fetchBatch,
                            'start':inCnt
                        }
                    )
                deviceResponse = deviceResponse['result']
                for device in deviceResponse['searchResults']:
                    data.append(device)
                inCnt += fetchBatch
        else:
            """ If the devices count is less than the fetchBatch(number of devices to fetch in each run)
                fetch all the devices in one run and append the device data into data[] array.
            """
            #Get full list of devices.
            deviceResponse = self._http_request(
                    method='GET',
                    url_suffix='/api/v1/device',
                    params={
                        'dmPartitionId':dm_partition_id,
                        'fq':query
                    }
                )
            deviceResponse = deviceResponse['result']
            for device in deviceResponse['searchResults']:
                data.append(device)
        """ return the value back to the fetch_incidents function.
        """
        return data

    def get_device_severity(self, deviceInfo : Dict[str, Any]) -> str:

        """
        Function to find the device severity based on conditions given below

        type deviceInfo:Dict

        returns severity after converting to XSOAR severity in the type of Int

        """

        severity = convert_to_demisto_severity('Low')
        if (deviceInfo['jailbroken']):
            severity = convert_to_demisto_severity('Critical')
            return severity
        elif (deviceInfo['complianceState']) == False :
            severity = convert_to_demisto_severity('High')
            return severity
        elif deviceInfo['quarantined']:
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
        url='/api/v1/device/'+ action_str
        return self._http_request(
                    method=method_type,
                    url_suffix=url,
                    params={'ids':deviceid}
            )

    def send_message(self, pushmessage:str,subject: str, message: str, dm_partition_id: str, deviceid: str ) -> Dict[str, Any]:
        """Execute send message action to Mobileiron CORE based on the conditions.

        :type pushmessag: ``str``
        :param pushmessag: Pushmessage to send notification using push message.
        :type subject: ``str``
        :param subject: Subject for the email
        :type message: ``str``
        :param message: Message for the email
        :type dm_partition_id: ``str``
        :param dm_partition_id: Partition ID for the device.
        :type deviceid: ``str``
        :param deviceid: DeviceID on which the actions should be performed..


        :return: dict containing the scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='PUT',
            url_suffix='/api/v1/device/message',
            params={
                'sendPushNotification':True,
                'pushNotificationMessage':pushmessage,
                'sendEmail':True,
                'emailSubject':subject,
                'emailBody':message,
                'dmPartitionId':dm_partition_id,
                'deviceIds':deviceid
            }
        )

    def ping_url(self):
        """Executes PING ´to check for the connection with Mobileiron CLOUD.

        :return: Demisto.results(ok)
        """

        response = self._http_request(
            method='GET',
            url_suffix='/api/v1/tenant/partition/device'
        )
        if (response) and (response["result"]):
            demisto.results('ok')



def rename_keys(event_input:Dict[str, Any], keys:Dict[str, Any])-> Dict[str, Any]:
    """ Function to rename/translate keys from the API Response

        :type event_input: ``str``
        :param event_input: Each device information retrieved from CLOUD.
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
    """Maps Mobileiron severity to Cortex XSOAR severity

    Converts the HelloWorld alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the analyzed function (str)

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

def execute_command(client: MobileironClient, args: Dict[str, Any], action_str: str, method_type: str ) -> CommandResults:
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

    deviceid = args.get('device_id',None)
    action_str=action_str
    response = client.execute_action(action_str=action_str, deviceid=deviceid, method_type=method_type)

    validation = response["result"]
    if validation == 1:
        results = { 'cmd_result':True ,
                    'err_code':0,
                    'err_message':'Command has been executed sucessfully'
                  }

        return CommandResults(
            #readable_output=readable_output,
            outputs_prefix='Mobileiron',
            outputs_key_field='cmd_result',
            outputs=results
        )
    else:
        raise ValueError("Failed to perform the action on the device .... Please verify manually")


def ping_url(client: MobileironClient):
    """ This definition is for test command to get Ping response from Cloud"""

    response = client.ping_url()



def fetch_incidents(client: MobileironClient ) -> List[Dict[str, Any]] :
    """This function returns incidents after analyzing the response data

    This function has to implement the logic of making sure that incidents are
    fetched based on analyzing the response data. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :return:
        incidents are returned in the form of dict
    """

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []
    devices_response = client.get_devices_data()

    for device in devices_response:

        #If no name is present it will throw an exception
        incident_name = device['deviceModel']

        #Rename keys for device attributes
        modified_device = rename_keys(device, translation_cloud)
        #Get severity based on conditions given in getDeviceSeverity function
        severity = client.get_device_severity(device)

        # INTEGRATION DEVELOPER TIP
        # The incident dict is initialized with a few mandatory fields:
        # name: the incident name
        # occurred: the time on when the incident occurred, in ISO8601 format
        # we use timestamp_to_datestring() from CommonServerPython.py to
        # handle the conversion.
        # rawJSON: everything else is packed in a string via json.dumps()
        # and is included in rawJSON. It will be used later for classification
        # and mapping inside XSOAR.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSOAR specific severity (int 1 to 4)
        # Note that there are other fields commented out here. You can do some
        # mapping of fields (either out of the box fields, like "details" and
        # "type") or custom fields (like "helloworldid") directly here in the
        # code, or they can be handled in the classification and mapping phase.
        # In either case customers can override them. We leave the values
        # commented out here, but you can use them if you want.
        incident = {
            'name': incident_name,
            'rawJSON': json.dumps(modified_device),
            'type': 'UEM Device Cloud',  # Map to a specific XSOAR incident Type
            'severity': severity
        }

        incidents.append(incident)

    return incidents


def get_devices_data_command(client: MobileironClient, args: Dict[str, Any]) -> CommandResults:
    """get_devicesData: Returns a list of all devices from mobileiron system

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
    devices_data = devices_data_response["result"]
    devices_data = devices_data["searchResults"]
    #readable_output = tableToMarkdown(f'Device List', devices_data)

    return CommandResults(
        #readable_output=readable_output,
        outputs_prefix='Mobileiron.DevicesInfo',
        outputs_key_field='devices_data',
        outputs=devices_data
    )


def send_message_command(client: MobileironClient, args: Dict[str, Any]) -> CommandResults:

    """mobileiron-send-message command: Returns results for a Mobileiron PostAction

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

    deviceid = args.get('device_id',None)
    pushmessage = args.get('pushmessage',None)
    message = args.get('message',None)
    subject = args.get('subject',None)
    #raise ValueError(send_message_url)

    response = client.send_message(pushmessage,subject,message,dm_partition_id,deviceid)
    validation = response["result"]
    if validation:
        results = { 'cmd_result':True ,
                    'err_code':0,
                    'err_message':'Command has been executed sucessfully'
                  }

        return CommandResults(
            #readable_output=readable_output,
            outputs_prefix='Mobileiron',
            outputs_key_field='cmd_result',
            outputs=results
        )
    else:
        raise ValueError("Failed to perform the action on the device .... Please verify manually")



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
            #Code For changing the pull incidents with timeline.
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
            #End of skip based on the time interval.


            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents = fetch_incidents(
                client=client
            )
            # fetch-incidents calls ``demisto.incidents()`` to provide the list of incidents to create
            demisto.incidents(incidents)
            demisto.setLastRun({'time': current_run_time})

        elif demisto.command() == 'mobileiron-get-devices-data':
            # To get the list of devices data with the given parameters..
            return_results(get_devices_data_command(client, demisto.args()))

        elif demisto.command() == 'mobileiron-unlock-device':
            # Post Action to unclock a Fetched device based on device id
            return_results(execute_command(client, demisto.args(),"unlock", "PUT"))

        elif demisto.command() == 'mobileiron-retire-device':
            # Post Action to retire a Fetched device based on device id
            return_results(execute_command(client, demisto.args(),"retire", "PUT"))

        elif demisto.command() == 'mobileiron-wipe_device':
            # Post Action to wipe a Fetched device based on device id
            return_results(execute_command(client, demisto.args(),"wipe", "PUT"))

        elif demisto.command() == 'mobileiron-force-check-in':
            # Post Action to force checkin a Fetched device based on device id
            return_results(execute_command(client, demisto.args(),"forceCheckin", "PUT"))

        elif demisto.command() == 'mobileiron-send-message':
            # Post Action to send a message to Fetched device based on device id
            return_results(send_message_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()