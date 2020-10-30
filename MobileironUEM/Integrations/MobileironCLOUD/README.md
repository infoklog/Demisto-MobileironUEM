Mobileiron CLOUD Integration
This integration was integrated and tested with version xx of MobileironCLOUD
## Configure MobileironCLOUD on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MobileironCLOUD.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://eu1.mobileiron.com) | True |
| credentials | User Name | True |
| isFetch | Fetch incidents | True |
| incidentType | Incident type | False |
| dmPartitionId | Partition ID\(e.g.33533\) | True |
| query | Query | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| fetch_interval | Fetch Interval\(in minutes\) | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mobileiron-get-devices-data
***
This command is used to get devices data to the particular device based on device id




### mobileiron-unlock-device
***
This command is used to unlock device to the particular device based on device id


#### Base Command

`mobileiron-unlock-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron unlock device only command | Optional | 
| platform | This argument fetches the platform for mobileiron unlock device only command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for unlock device only | 
| Mobileiron.err_code | boolean | Command code for unlock device only | 
| Mobileiron.err_message | String | Command message for unlock device only | 


#### Command Example
`!mobileiron-unlock-device device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-retire-device
***
This command is used to retire device to the particular device based on device id


#### Base Command

`mobileiron-retire-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron retire device command | Optional | 
| platform | This argument fetches the platform for mobileiron retire device command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for retire device | 
| Mobileiron.err_code | boolean | Command code for retire device | 
| Mobileiron.err_message | String | Command message for retire device | 


#### Command Example
`!mobileiron-retire-device device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully |



### mobileiron-wipe-device
***
This command is used to wipe device to the particular device based on device id


#### Base Command

`mobileiron-wipe-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron wipe device command | Optional | 
| platform | This argument fetches the platform for mobileiron wipe device command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for wipe device | 
| Mobileiron.err_code | boolean | Command code for wipe device | 
| Mobileiron.err_message | String | Command message for wipe device | 


#### Command Example
`!mobileiron-wipe-device device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully |




### mobileiron-force-check-in
***
This command is used to force checkin to the particular device based on device id


#### Base Command

`mobileiron-force-check-in`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron force checkin command | Optional | 
| platform | This argument fetches the platform for mobileiron force checkin command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for force checkin | 
| Mobileiron.err_code | boolean | Command code for force checkin | 
| Mobileiron.err_message | String | Command message for force checkin | 


#### Command Example
`!mobileiron-force-check-in device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully |



### mobileiron-send-message
***
This command is used to send a message to the particular device based on device id


#### Base Command

`mobileiron-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron send message command | Optional | 
| platform | This argument fetches the platform for mobileiron send message command | Optional | 
| pushmessage | Provide push notification message for email | Required | 
| subject | Provide Subject for email | Required | 
| message | Provide message for email | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for send message | 
| Mobileiron.err_code | boolean | Command code for send message | 
| Mobileiron.err_message | String | Command message for send message | 


#### Command Example
`!mobileiron-send-message device_id:"device_id" platform:"Android" pushmessage:"email" subject:"Subject for email" message:"Message for email"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully |
#### Base Command

`mobileiron-get-devices-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.DevicesInfo | String | Fetches the data from devices | 