# packet_parser
Python script that parses packet captures for unique identifiers

# Installation
Install requirements:

`pip install -r requirements.txt`

# Use
Run the script with the pcap file as an argument:

`python pcap_parser.py <example.pcap>`

Enter a number to search for a default unique identifier or input your own term to search for:

![image](https://user-images.githubusercontent.com/45744428/130127128-066e7450-3d79-4e1c-a475-d1fd555f52d5.png)

Here we enter 0 to search for Android IDs:

![image](https://user-images.githubusercontent.com/45744428/130127762-ded7b2c4-bcfd-45d4-bd56-5dfa1a29e9aa.png)

We find two unique IDs found in 36 and 3 packets respectively.

We can now choose to save these results to a file by entering 'y' and inputting a file name:

![image](https://user-images.githubusercontent.com/45744428/130128091-f8f7894c-000f-4785-8168-b5f92600b06b.png)

The file is now saved as a json.

From here you can peruse the packet results, organized by packet number:

![image](https://user-images.githubusercontent.com/45744428/130130780-b6160694-3693-416f-b2c2-a8153d630eb2.png)
 
 Key:
 
    "0000000000000000000": {              # The value of the unique identifier found
        "999": {                          # The packet number
            "MAC_destination": string     # Media Access Control address destination
            "MAC_source": string,         # Media Access Control address source
            "accept_language": string,    # Accept-Language HTTP request header
            "browser": string,            # Browser used
            "device_brand": string,       # Device brand
            "device_model": string,       # Device model name/number
            "is_PC?": boolean,            # Is this device a personal computer?
            "is_bot?": boolean,           # Is this device a bot (e.g. web crawler)?
            "is_mobile?": boolean,        # Is this a mobile device?
            "is_tablet?": boolean,        # Is the device a tablet?
            "is_touch_capable?": boolean, # Is this a touch capable device?
            "os": string,                 # Device operating system
            "packet_object":              # The full packet object in string form
            "unique_IDs": list,           # A list of other unique IDs found in this packet
            "user_agent": string          # The full user-agent string
            
 # Associating Unique Identifiers
 
 If other unique IDs are found within packets containing the originally searched term, these will be returned upon search completion:
 
![image](https://user-images.githubusercontent.com/45744428/130142558-4fd7eef5-241a-4ede-a8e2-5a141fa563f1.png)



