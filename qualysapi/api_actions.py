from __future__ import absolute_import
from lxml import objectify
import xmltodict
import qualysapi.api_objects
from qualysapi.api_objects import *

# pylint: disable=I0011, C0103

class QGActions(object):
    """QualysGuard API Query Actions."""

    def getHost(self, host_ip=''):
        """
        Get Host record from API.

        Keyword Args:
            host_ip (str): Host IP address.

        Returns:
            (Host): Host object.
        """
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': host_ip, 'details': 'All'}

        host_data = self._request_and_parse_response(call, parameters) \
                        ['host_list_output']['response']

        # Host exists in result set
        try:
            if 'host' in host_data['host_list']:
                return Host(**host_data['host_list']['host'])

        # Return empty Host
        except KeyError:
            return Host('', '', host_ip, 'never', '', '', '')

    def getHostRange(self, start_ip='', end_ip=''):
        """
        Get Host records from API by IP range.

        Keyword Args:
            start_ip (str): IP range start address.
            end_ip (str): IP range end address.

        Yields:
            (Host): Host instances.
        """
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list',
                      'ips': '{0}-{1}'.format(start_ip, end_ip)}

        host_data = self._request_and_parse_response(call, parameters) \
                        ['host_list_output']['response']

        # Hosts exist in result set
        try:
            if 'host' in host_data['host_list']:
                for host in host_data['host_list']['host']:
                    yield Host(**host)

        # Return empty Host
        except KeyError:
            return []

    def listAssetGroups(self, groupName=''):
        """Get Asset Groups."""
        call = 'asset_group_list.php'

        if groupName == '':
            agData = objectify.fromstring(self.request(call))
        else:
            agData = \
                objectify.fromstring(self.request(call, 'title='+groupName)) \
                         .RESPONSE
            
        groupsArray = []
        scanipsArray = []
        scandnsArray = []
        scannersArray = []

        for group in agData.ASSET_GROUP:
            try:
                for scanip in group.SCANIPS:
                    scanipsArray.append(scanip.IP)

            # No IPs defined to scan.
            except AttributeError:
                scanipsArray = []
                
            try:
                for scanner in group.SCANNER_APPLIANCES.SCANNER_APPLIANCE:
                    scannersArray.append(scanner.SCANNER_APPLIANCE_NAME)

            # No scanner appliances defined for this group.
            except AttributeError:
                scannersArray = []
                
            try:
                for dnsName in group.SCANDNS:
                    scandnsArray.append(dnsName.DNS)

            # No DNS names assigned to group.
            except AttributeError:
                scandnsArray = []
                
            groupsArray.append(AssetGroup(group.BUSINESS_IMPACT,
                                          group.ID,
                                          group.LAST_UPDATE,
                                          scanipsArray,
                                          scandnsArray,
                                          scannersArray,
                                          group.TITLE))
            
        return groupsArray
        
       
    def listReportTemplates(self):
        """List Report Templates."""
        call = 'report_template_list.php'

        rtData = objectify.fromstring(self.request(call))
        templatesArray = []
        
        for template in rtData.REPORT_TEMPLATE:
            templatesArray.append(ReportTemplate(template.GLOBAL,
                                                 template.ID,
                                                 template.LAST_UPDATE,
                                                 template.TEMPLATE_TYPE,
                                                 template.TITLE,
                                                 template.TYPE,
                                                 template.USER))
        
        return templatesArray
        
    def listReports(self, id=0):
        """List Reports."""
        call = '/api/2.0/fo/report'
        
        if id == 0:
            parameters = {'action': 'list'}
            
            repData = \
                objectify.fromstring(self.request(call, parameters)).RESPONSE
            reportsArray = []
        
            for report in repData.REPORT_LIST.REPORT:
                reportsArray.append(Report(report.EXPIRATION_DATETIME,
                                           report.ID,
                                           report.LAUNCH_DATETIME,
                                           report.OUTPUT_FORMAT,
                                           report.SIZE,
                                           report.STATUS,
                                           report.TYPE,
                                           report.USER_LOGIN))
        
            return reportsArray
            
        else:
            parameters = {'action': 'list', 'id': id}
            repData = objectify.fromstring(self.request(call, parameters)) \
                               .RESPONSE.REPORT_LIST.REPORT

            return Report(repData.EXPIRATION_DATETIME,
                          repData.ID,
                          repData.LAUNCH_DATETIME,
                          repData.OUTPUT_FORMAT,
                          repData.SIZE,
                          repData.STATUS,
                          repData.TYPE,
                          repData.USER_LOGIN)

    def notScannedSince(self, days):
        """
        Get Hosts not scanned within specified number of days.

        Args:
            days (int): Number of days since last scanned.

        Yields:
            (Host): Host instances.
        """
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'details': 'All'}

        host_data = self._request_and_parse_response(call, parameters) \
                        ['host_list_output']['response']

        today = datetime.date.today()

        # Hosts exist in result set
        try:
            if 'host' in host_data['host_list']:
                for host in host_data['host_list']['host']:
                    last_scan = \
                        str(host['last_vuln_scan_datetime']).split('T')[0]

                    last_scan = datetime.date(int(last_scan.split('-')[0]),
                                              int(last_scan.split('-')[1]),
                                              int(last_scan.split('-')[2]))

                    if (today - last_scan).days >= days:
                        yield Host(**host)

        # Return empty Host
        except KeyError:
            return []
        
    def addIP(self, ips, vmpc):
        """Add IP address."""
        # 'ips' parameter accepts comma-separated list of IP addresses.
        # 'vmpc' parameter accepts 'vm', 'pc', or 'both'.
        # (Vulnerability Managment, Policy Compliance, or both)
        call = '/api/2.0/fo/asset/ip/'

        enablevm = 1
        enablepc = 0

        if vmpc == 'pc':
            enablevm = 0
            enablepc = 1

        elif vmpc == 'both':
            enablevm = 1
            enablepc = 1
            
        parameters = {'action': 'add',
                      'ips': ips,
                      'enable_vm': enablevm,
                      'enable_pc': enablepc}

        self.request(call, parameters)

    def listScans(self, launched_after=None, state=None, target=None,
                  scan_type=None, user_login=None):
        """
        List scans.

        Keyword Args:
            launched_after (str): Date in YYYY-MM-DD format.
            state (str): 'Running', 'Paused', 'Canceled', 'Finished',
                         'Error', 'Queued', or 'Loading'.
            title (str): Scan title.
            type (str): 'On-Demand' or 'Scheduled'
            user_login (str): Username.

        Yields:
            (Scan): Scan instances.
        """
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list',
                      'show_ags': 1,
                      'show_op': 1,
                      'show_status': 1}

        if launched_after is not None:
            parameters['launched_after_datetime'] = launched_after
           
        if state is not None:
            parameters['state'] = state
           
        if target is not None:
            parameters['target'] = target
           
        if scan_type is not None:
            parameters['type'] = scan_type

        if user_login is not None:
            parameters['user_login'] = user_login

        scan_data = self._request_and_parse_response(call, parameters) \
                        ['scan_list_output']['response']

        # Scans exist in result set
        try:
            if 'scan' in scan_data['scan_list']:
                for scan in scan_data['scan_list']['scan']:
                    try:
                        title_list = \
                            scan['asset_group_title_list']['asset_group_title']

                        if isinstance(title_list, list):
                            ag_list = title_list
                        else:
                            ag_list = [title_list]

                    except (AttributeError, KeyError):
                        ag_list = []

                    yield Scan(asset_groups=ag_list, **scan)

        # Return empty result set
        except KeyError as err:
            return []
        
    def launchScan(self, title, option_title,
                   iscanner_name, asset_groups="", ip=""):
        """
        Launch Scan.

        TODO:
            - Add ability to scan by tag.
        """
        call = '/api/2.0/fo/scan/'

        parameters = {'action': 'launch',
                      'scan_title': title,
                      'option_title': option_title,
                      'iscanner_name': iscanner_name,
                      'ip': ip,
                      'asset_groups': asset_groups}

        if ip == "":
            parameters.pop("ip")
        
        if asset_groups == "":
            parameters.pop("asset_groups")
            
        scan_ref = objectify.fromstring(self.request(call, parameters)) \
                            .RESPONSE.ITEM_LIST.ITEM[1].VALUE
        
        call = '/api/2.0/fo/scan/'

        parameters = {'action': 'list',
                      'scan_ref': scan_ref,
                      'show_status': 1,
                      'show_ags': 1,
                      'show_op': 1}
        
        scan = objectify.fromstring(self.request(call, parameters)) \
                        .RESPONSE.SCAN_LIST.SCAN

        try:
            agList = []
            for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                agList.append(ag)

        except AttributeError:
            agList = []
        
        return Scan(agList,
                    scan.DURATION,
                    scan.LAUNCH_DATETIME,
                    scan.OPTION_PROFILE.TITLE,
                    scan.PROCESSED,
                    scan.REF,
                    scan.STATUS,
                    scan.TARGET,
                    scan.TITLE,
                    scan.TYPE,
                    scan.USER_LOGIN)

    def _request_and_parse_response(self, call, parameters):
        """
        Query API, parse and return response.
        
        Args:
            call (str): URL path to API call.
            parameters (dict): Query parameters.

        Returns:
            (dict): Parse response from API.
        """
        response = lower_keys(xmltodict.parse(self.request(call, parameters),
                                              dict_constructor=dict,
                                              xml_attribs=True,
                                              encoding='utf-8'))

        return response

    # PEP8 cleanup, preserved method names for backwards-compatibility
    get_host = getHost
    get_hosts_within_ip_range = getHostRange
    get_hosts_not_scanned_since = notScannedSince
    get_scans = listScans


def lower_keys(x):
    """Lowercase dict keys."""
    if isinstance(x, list):
        return [lower_keys(v) for v in x]

    elif isinstance(x, dict):
        return dict((k.lower(), lower_keys(v)) for k, v in x.items())

    else:
        return x
