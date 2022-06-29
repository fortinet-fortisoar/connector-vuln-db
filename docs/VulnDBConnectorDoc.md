## About the connector
VulnDB is the most comprehensive and timely vulnerability intelligence available and provides actionable information about the latest in security vulnerabilities. This connector facilitates the automated operations related to vulnerabilities, products, and vendors.
<p>This document provides information about the VulnDB Connector, which facilitates automated interactions, with a VulnDB server using FortiSOAR&trade; playbooks. Add the VulnDB Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with VulnDB.</p>
### Version information

Connector Version: 1.0.0


Authored By: Community

Certified: No
## Installing the connector
<p>From FortiSOAR&trade; 5.0.0 onwards, use the <strong>Connector Store</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.<br>You can also use the following <code>yum</code> command as a root user to install connectors from an SSH session:</p>
`yum install cyops-connector-vuln-db`

## Prerequisites to configuring the connector
- You must have the URL of VulnDB server to which you will connect and perform automated operations and credentials to access that server.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the VulnDB server.

## Minimum Permissions Required
- N/A

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>VulnDB</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations&nbsp;</strong> tab enter the required configuration details:&nbsp;</p>
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Server URL<br></td><td>The service-based URI to which you will connect and perform the automated operations.<br>
<tr><td>Client ID<br></td><td>Unique Client ID of the VulnDB that is used to create an authentication token required to access the VulnDB API.<br>
<tr><td>Client Secret<br></td><td>Unique Client Secret of the VulnDB that is used to create an authentication token required to access the API.<br>
<tr><td>Verify SSL<br></td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set as True.<br></td></tr>
</tbody></table>
## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function<br></th><th>Description<br></th><th>Annotation and Category<br></th></tr></thead><tbody><tr><td>Get Vulnerability List<br></td><td>Retrieves a list of all vulnerabilities from VulnDB based on the start time, end time or other input parameters you have specified.<br></td><td>get_vuln_list <br/>Investigation<br></td></tr>
<tr><td>Get Vulnerability Details<br></td><td>Retrieves details of a specific vulnerability from VulnDB based on the filter or other input parameter you have specified.<br></td><td>get_vuln_details <br/>Investigation<br></td></tr>
<tr><td>Get Vendor Details<br></td><td>Retrieves details of a list of all vendors or specific vendor from VulnDB based on the vendor ID, vendor name or other input parameters you have specified.<br></td><td>get_vendor_details <br/>Investigation<br></td></tr>
<tr><td>Get Product Details<br></td><td>Retrieves details of a list of all products or specific product from VulnDB based on the vendor ID, vendor name or other input parameters you have specified.<br></td><td>get_product_details <br/>Investigation<br></td></tr>
<tr><td>Get Product Version<br></td><td>Retrieves version of a specific product from VulnDB based on the product ID, product name or other input parameters you have specified.<br></td><td>get_product_version <br/>Investigation<br></td></tr>
<tr><td>Get Vulnerability By Vendor and Product<br></td><td>Retrieves a list of all vulnerabilities from VulnDB based on the vendor ID, product ID or other input parameters you have specified.<br></td><td>get_vuln_by_vendor_and_product <br/>Investigation<br></td></tr>
</tbody></table>
### operation: Get Vulnerability List
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Start Date<br></td><td>Start date and time from when you want to retrieve vulnerabilities from the VulnDB.<br>
</td></tr><tr><td>End Date<br></td><td>End date and time till when you want to retrieve vulnerabilities from the VulnDB.<br>
</td></tr><tr><td>Limit<br></td><td>(Optional) Maximum number of records that this operation should retrieve from the VulnDB.<br>
</td></tr></tbody></table>
#### Output

 The output contains a non-dictionary value.
### operation: Get Vulnerability Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Filter By<br></td><td>Filter a vulnerabilities whose details you want to retrieve from VulnDB.<br>
<strong>If you choose 'Vulnerability ID'</strong><ul><li>Vulnerability ID: ID of the vulnerability whose details you want to retrieve from VulnDB.</li></ul><strong>If you choose 'Vendor ID'</strong><ul><li>Vendor ID: ID of the vendor whose vulnerability details you want to retrieve from VulnDB.</li></ul><strong>If you choose 'Product ID'</strong><ul><li>Product ID: ID of the product whose vulnerability details you want to retrieve from VulnDB.</li></ul><strong>If you choose 'CVE ID'</strong><ul><li>CVE ID: ID of the cve whose vulnerability details you want to retrieve from VulnDB.</li></ul></td></tr><tr><td>Limit<br></td><td>(Optional) Maximum number of records that this operation should retrieve from the VulnDB.<br>
</td></tr></tbody></table>
#### Output

 The output contains a non-dictionary value.
### operation: Get Vendor Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Vendor<br></td><td>Specify a vendor whose details you want to retrieve from VulnDB.<br>
<strong>If you choose 'Vendor ID'</strong><ul><li>Vendor ID: ID of the vendor whose details you want to retrieve from VulnDB.</li></ul><strong>If you choose 'Vendor Name'</strong><ul><li>Vendor Name: Name of the vendor whose details you want to retrieve from VulnDB.</li></ul></td></tr><tr><td>Limit<br></td><td>(Optional) Maximum number of records that this operation should retrieve from the VulnDB.<br>
</td></tr></tbody></table>
#### Output

 The output contains a non-dictionary value.
### operation: Get Product Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Vendor<br></td><td>Specify a vendor whose details you want to retrieve from VulnDB.<br>
<strong>If you choose 'Vendor ID'</strong><ul><li>Vendor ID: ID of the vendor whose details you want to retrieve from VulnDB.</li></ul><strong>If you choose 'Vendor Name'</strong><ul><li>Vendor Name: Name of the vendor whose details you want to retrieve from VulnDB.</li></ul></td></tr><tr><td>Limit<br></td><td>(Optional) Maximum number of records that this operation should retrieve from the VulnDB.<br>
</td></tr></tbody></table>
#### Output

 The output contains a non-dictionary value.
### operation: Get Product Version
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Product<br></td><td>Specify a product whose version details you want to retrieve from VulnDB.<br>
<strong>If you choose 'Product ID'</strong><ul><li>Product ID: ID of the product whose version details you want to retrieve from VulnDB.</li></ul><strong>If you choose 'Vendor Name'</strong><ul><li>Product Name: Name of the product whose version details you want to retrieve from VulnDB.</li></ul></td></tr><tr><td>Limit<br></td><td>(Optional) Maximum number of records that this operation should retrieve from the VulnDB.<br>
</td></tr></tbody></table>
#### Output

 The output contains a non-dictionary value.
### operation: Get Vulnerability By Vendor and Product
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Vendor ID<br></td><td>ID of the vendor whose vulnerability details you want to retrieve from VulnDB.<br>
</td></tr><tr><td>Product ID<br></td><td>ID of the product whose vulnerability details you want to retrieve from VulnDB.<br>
</td></tr><tr><td>Limit<br></td><td>(Optional) Maximum number of records that this operation should retrieve from the VulnDB.<br>
</td></tr></tbody></table>
#### Output

 The output contains a non-dictionary value.
## Included playbooks
The `Sample - vuln-db - 1.0.0` playbook collection comes bundled with the VulnDB connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR<sup>TM</sup> after importing the VulnDB connector.

- Get Product Details
- Get Product Version
- Get Vendor Details
- Get Vulnerability By Vendor and Product
- Get Vulnerability Details
- Get Vulnerability List

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection, since the sample playbook collection gets deleted during connector upgrade and delete.
