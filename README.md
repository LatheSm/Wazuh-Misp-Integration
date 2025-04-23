# Wazuh-Misp-Integration
Custom Integration Code to Connect a MISP API Hosted on your Network to your Wazuh System. Then Code to create an Active Response Executable that will delete any file that has a matching SHA256 hash with an IOC file. Used Virus Total and another Integration program as a base so ignore the variables having names like client_ip, when it is actually the sha256 hash variable.
