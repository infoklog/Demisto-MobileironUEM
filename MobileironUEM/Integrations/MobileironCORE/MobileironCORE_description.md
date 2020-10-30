This is the MobileironCORE integration for getting started.
This integration was integrated and tested with version xx of MobileironCORE
## Configure MobileironCORE on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MobileironCORE.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://core.mobileiron.com) | True |
| credentials | Username | True |
| adminDeviceSpaceId | Device ID | True |
| query | Query | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| additionalfields | Additional Fields | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| subject | Provide Subject for email | Required | 
| message | Provide message for email | Required | 
| push_message | Push Message Mode | Required | 


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



### mobileiron-update-os
***
This command is used to update OS to the particular device based on device id


#### Base Command

`mobileiron-update-os`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron update os command | Optional | 
| platform | This argument fetches the platform for mobileiron update os command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for update OS | 
| Mobileiron.err_code | boolean | Command code for update OS | 
| Mobileiron.err_message | String | Command message for update OS | 


#### Command Example
`!mobileiron-update-os device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-unlock-device-only
***
This command is used to unlock device to the particular device based on device id


#### Base Command

`mobileiron-unlock-device-only`
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
| Mobileiron.err_message | boolean | Command message for unlock device only | 


#### Command Example
`!mobileiron-unlock-device-only device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-enable-voice-roaming
***
This command is used to enable voice roaming to the particular device based on device id


#### Base Command

`mobileiron-enable-voice-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron enable voice roaming command | Optional | 
| platform | This argument fetches the platform for mobileiron enable voice roaming command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for enable voice roaming | 
| Mobileiron.err_code | boolean | Command code for enable voice roaming | 
| Mobileiron.err_message | String | Command message for enable voice roaming | 


#### Command Example
`!mobileiron-enable-voice-roaming device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-disable-voice-roaming
***
This command is used to disable voice roaming to the particular device based on device id


#### Base Command

`mobileiron-disable-voice-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron disable voice roaming command | Optional | 
| platform | This argument fetches the platform for mobileiron disable voice roaming command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for disable voice roaming | 
| Mobileiron.err_code | boolean | Command code for disable voice roaming | 
| Mobileiron.err_message | String | Command message for disable voice roaming | 


#### Command Example
`!mobileiron-disable-voice-roaming device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-enable-data-roaming
***
This command is used to enable data roaming to the particular device based on device id


#### Base Command

`mobileiron-enable-data-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron enable data roaming command | Optional | 
| platform | This argument fetches the platform for mobileiron enable data roaming command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for enable data roaming | 
| Mobileiron.err_code | boolean | Command code for enable data roaming | 
| Mobileiron.err_message | String | Command message for enable data roaming | 


#### Command Example
`!mobileiron-enable-data-roaming device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-disable-data-roaming
***
This command is used to disable data roaming to the particular device based on device id


#### Base Command

`mobileiron-disable-data-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron disable data roaming command | Optional | 
| platform | This argument fetches the platform for mobileiron disable data roaming command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for disable data roaming | 
| Mobileiron.err_code | boolean | Command code for disable data roaming | 
| Mobileiron.err_message | String | Command message for disable data roaming | 


#### Command Example
`!mobileiron-disable-data-roaming device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-enable-personal-hotspot
***
This command is used to enable personal hotspot to the particular device based on device id


#### Base Command

`mobileiron-enable-personal-hotspot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron enable personal hotspot command | Optional | 
| platform | This argument fetches the platform for mobileiron enable personal hotspot command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for enable personal hotspot | 
| Mobileiron.err_code | boolean | Command code for enable personal hotspot | 
| Mobileiron.err_message | String | Command message for enable personal hotspot | 


#### Command Example
`!mobileiron-enable-personal-hotspot device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-disable-personal-hotspot
***
This command is used to disable personal hotspot to the particular device based on device id


#### Base Command

`mobileiron-disable-personal-hotspot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron disable personal hotspot command | Optional | 
| platform | This argument fetches the platform for mobileiron disable personal hotspot command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for disable personal hotspot | 
| Mobileiron.err_code | boolean | Command code for disable personal hotspot | 
| Mobileiron.err_message | String | Command message for disable personal hotspot | 


#### Command Example
`!mobileiron-disable-personal-hotspot device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-unlock-app-connect-container
***
This command is used to unlock app connect container to the particular device based on device id


#### Base Command

`mobileiron-unlock-app-connect-container`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron unlock app connect container command | Optional | 
| platform | This argument fetches the platform for mobileiron unlock app connect container command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mobileiron.cmd_result | String | Command result for unlock app connect contianer | 
| Mobileiron.err_code | boolean | Command code for unlock app connect container | 
| Mobileiron.err_message | String | Command message for unlock app connect container | 


#### Command Example
`!mobileiron-unlock-app-connect-container device_id:"device_id" platform:"Android"`

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



### mobileiron-force-checkin
***
This command is used to force checkin to the particular device based on device id


#### Base Command

`mobileiron-force-checkin`
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
`!mobileiron-force-checkin device_id:"device_id" platform:"Android"`

#### Human Readable Output
| **Path** |**Description** |
| --- | --- |
| cmd_result | true | 
| err_code |0 | 
| err_message |Command has been executed sucessfully | 



### mobileiron-get-devices-data
***
This command is used to get devices data to the particular device based on device id


#### Base Command

`mobileiron-get-devices-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIron.DevicesInfo | String | Fetches the data from devices | 



