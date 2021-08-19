import sys
import pyshark
from user_agents import parse
import pp
from itertools import islice
import progressbar
import re
import json

delimiter_chars = {"\\", "&", ";"} # chars that indicate the termination of a value
equals_chars = {":", "="} # chars the separate the term from the info
buffer_length = 5 # this is to ensure there is data following a search term
# The default search terms can be selected from a list for searching. Each is a tuple with the name of
# an identifier and the actual string to be located. To add new identifiers, simply add to this list.
default_search_terms = [('Android ID'           , 'androidId'), 
                        ('Facebook Cookie'      , 'c_user='),
                        ('Google Advertising ID', 'X-Ad-Id:'),
                        ('Youtube Cookie'       , 'VISITOR_INFO1_LIVE=')
                       ]


# Retrieves user unique identifier name and searchable string in a user-friendly way
def get_user_input():
    search_term_title = ''
    print("Enter number to select default search term:")
    for term in default_search_terms:
        print(f'{default_search_terms.index(term):3} : {term[0]:25}')
    search_term = input("Enter custom unique identifier or pick a number from the list:\n")
    if search_term.isnumeric() and int(search_term) < len(default_search_terms) and int(search_term) > -1:
        search_term_title = default_search_terms[int(search_term)][0]
        search_term       = default_search_terms[int(search_term)][1]
    else:
        search_term_title = 'Custom Input: ' + search_term 
    return search_term_title, search_term

# Looks for search term in a packet
# Returns (True, search term's value) if found and (False, "Not Found") otherwise
def find_term(packet, search_term):
    search_term = search_term.lower()
    lines = str(packet).splitlines()
    for line in lines:
        term_index = line.lower().find(search_term)
        if term_index > -1:
            # Do not include search_term in string, just the value
            term_index += len(search_term) + 1
            result = ''
            while line[term_index] not in delimiter_chars:
                result += line[term_index]
                term_index += 1
                if term_index >= len(line): break
            result = re.sub('[^A-Za-z0-9]+', '', result) # Remove spaces and special characters.
            return True, result
    return False, "Not Found"

# Builds the result dict while iterating though all packets in a pcap
# Takes in pcap and number of packets within it. If this is not known, input -1 for packet_count.
def process_pcap(shark_cap, packet_count):
    search_term_title, search_term = get_user_input()
    print("Searching for: " + search_term_title)
    result_dict    = {}
    raw_user_agent = 'Not Found'
    all_other_unique_ids = {}
    # The progressbar can be run without knowing the total length. Use progressbar.UnknownLength in this case.
    with progressbar.ProgressBar(max_value = progressbar.UnknownLength if (packet_count < 0) else packet_count) as bar:
        for packet in shark_cap:
            found, result = find_term(packet, search_term)
            if found:
                # Initialize a dict within result_dict to contain all matching packets
                if result not in result_dict:
                    result_dict[result] = {}
                # Find any other Unique IDs within the packet
                other_unique_ids = []
                for term in default_search_terms:
                    if term[1] != search_term: 
                        found_inner, result_inner = find_term(packet, term[1])
                        if found_inner:
                            # If not previously added, add the unique ID to a list for that individual packet
                            if {term[0]: result_inner} not in other_unique_ids:
                                other_unique_ids.append({term[0]: result_inner})
                            # Add it to a larger dictionary of associated IDs to be displayed to the user after search is complete
                            if result not in all_other_unique_ids.keys():
                                all_other_unique_ids[result] = [{term[0]: result_inner}]
                            else:
                                if {term[0]: result_inner} not in all_other_unique_ids[result]:
                                    all_other_unique_ids[result].append({term[0]: result_inner})
                #Check if packet has a User Agent field before assigning
                if hasattr(packet, 'http') and hasattr(packet.http, 'user_agent'):
                    raw_user_agent = packet.http.user_agent
                    user_agent = parse(raw_user_agent) 
                    result_dict[result][packet.number] = {

                        "user_agent"        : raw_user_agent, 
                        "browser"           : user_agent.browser.family + ' ' + user_agent.browser.version_string,
                        "os"                : user_agent.os.family + ' ' + user_agent.os.version_string,
                        "device_brand"      : user_agent.device.brand,
                        "device_model"      : user_agent.device.model,
                        "is_mobile?"        : user_agent.is_mobile,
                        "is_tablet?"        : user_agent.is_tablet,
                        "is_touch_capable?" : user_agent.is_touch_capable,
                        "is_PC?"            : user_agent.is_pc,
                        "is_bot?"           : user_agent.is_bot,
                        "accept_language"   : find_term(packet, "Accept-Language")[1],
                        "MAC_source"        : packet.eth.src,
                        "MAC_destination"   : packet.eth.dst,
                        "packet_object"     : str(packet),
                        "unique_IDs"        : other_unique_ids,
                    } 
                # Results if packet does not contain a user_agent    
                else:
                    result_dict[result][packet.number] = {
                        "user_agent"        : "Not found",
                        "browser"           : "Not found",
                        "os"                : "Not found",
                        "device_brand"      : "Not found",
                        "device_model"      : "Not found",
                        "is_mobile?"        : "Not found",
                        "is_tablet?"        : "Not found",
                        "is_touch_capable?" : "Not found",
                        "is_PC?"            : "Not found",
                        "is_bot?"           : "Not found",
                        "accept_language"   : find_term(packet, "Accept-Language")[1],
                        "MAC_source"        : packet.eth.src,
                        "MAC_destination"   : packet.eth.dst,
                        "packet_object"     : str(packet),
                        "unique_IDs"        : other_unique_ids,
                    } 
            
            bar.update(int(packet.number)) # This is the number displayed next to the loading bar
            packet_count = int(packet.number)
    # After iterating through all packets, passes off results to handle_results function
    handle_results(result_dict, packet_count, search_term_title, shark_cap, all_other_unique_ids)

# Deals with user input after a search is complete and outputs results to the user.
def handle_results(result_dict, packet_count, search_term_title, shark_cap, all_other_unique_ids):
    print("Results for " + search_term_title +  " from " + str(packet_count) + " packets:")
    print("-----------------------------------------------")
    if result_dict:
        for key in result_dict:
            print(f'{key:25} = {str(len(result_dict[key])):4} Packets Found')
        if all_other_unique_ids:
            print("Other unique IDs found in these packets:")
            pp(all_other_unique_ids)
        save_file = input("Save results to file? (Y/n)")
        if save_file.lower() == 'y':
            fname = input("File name: ")
            json_to_save = json.dumps(result_dict, indent=4, sort_keys=True)
            f = open(fname + '.json', 'w')
            f.write(json_to_save)
            print("File saved as " + fname + ".json")
            f.close()
    # If no results were found, give user the option to search for a different term
    else: 
        run_again = input("No results for " + search_term_title +"\nSearch again? (Y/n)")
        if run_again.lower() == 'y':
            process_pcap(shark_cap, packet_count)
            
# Main function takes in pcap argument and calls process_pcap()
if __name__ == "__main__":
    # display_filter prevents hanging due to large media packets
    shark_cap = pyshark.FileCapture(sys.argv[1], display_filter = "!media and !mp4") 
    process_pcap(shark_cap, -1)
    


    #TODO add search by value feature
    #TODO add in search all default terms feature
    #TODO add cross referencing by mac address, and possibly other things like IP
    #TODO add "you need to specify pcap" text if no argument used
    #TODO add way to save unique identifier associations
    #TODO add live capture functionality

""" Helpful links:
On pyshark:
https://github.com/KimiNewt/pyshark/
http://kiminewt.github.io/pyshark/
https://thepacketgeek.com/pyshark/packet-object/

On user-agent parser:
https://pypi.org/project/user-agents/
"""