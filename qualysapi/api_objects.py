from __future__ import absolute_import
import datetime
import dateutil.parser
import xmltodict
from lxml import objectify
from ipaddress import (IPv4Address, IPv4Network, summarize_address_range)

"""Object representations of API data types."""


class Host(object):
    """Scanned Host."""

    def __init__(self, dns=None, id=None, ip=None,
                 last_vuln_scan_datetime=None, netbios=None, os=None,
                 tracking_method=None, **kwargs):
        """
        Initialize instance of Host.

        Keyword Args:
            dns (str): DNS hostname.
            id (int): ID.
            ip (str): IP Address.
            last_vuln_scan_datetime (str): Last scan date.
            netbios (str): NetBIOS name.
            os (str): Operating system.
            tracking_method (str): Scan tracking method.
        """
        self.dns = dns
        self.id = int(id)
        self.ip = ip

        self.last_scan = dateutil.parser.parse(last_vuln_scan_datetime) \
            if last_vuln_scan_datetime else None

        self.netbios = netbios
        self.os = os
        self.tracking_method = tracking_method


class AssetGroup(object):
    """Asset Group."""

    def __init__(self, business_impact=None, id=None, unit_id=None,
                 owner_id=None, network_id=None, last_update=None,
                 scan_ips=None, scan_dns=None, scanner_appliances=None,
                 title=None, ip_set=None, scandns=None, **kwargs):
        """
        Initialize instance of AssetGroup.

        Keyword Args:
            business_impact (str): Business impact.
            id (int): ID.
            unit_id (int): Unit ID.
            owner_id (int): Owner ID.
            network_id (int): Network ID.
            last_update (str): Last updated date.
            scan_ips (list): Scan IPs.
            scan_dns (str): Scan DNS.
            scanner_appliances (list): Scanner appliances.
            title (str): Asset Group title.
            ip_set (list): Scan IPs (as they come in from the API).
        """
        self.business_impact = str(business_impact)
        self.id = int(id)
        self.title = str(title)
        self.unit_id = unit_id
        self.owner_id = owner_id
        self.network_id = network_id
        self.last_update = dateutil.parser.parse(last_update)
        self.ip_ranges = set()

        # Scan IP address ranges
        if 'ip_range' in ip_set:
            for ip_range in ip_set['ip_range']:
                # Dash-delimited string
                if '-' in ip_range:
                    start_ip, end_ip = ip_range.split('-')
                    start_ip = IPv4Address(start_ip.strip())
                    end_ip = IPv4Address(end_ip.strip())

                    for ipn in summarize_address_range(start_ip, end_ip):
                        network = IPv4Network(ipn)
                        self.ip_ranges.add(network)

        # Single IP addresses
        if 'ip' in ip_set:
            for ip in ip_set['ip']:
                ip = IPv4Address(ip)

                for ipn in summarize_address_range(ip, ip):
                    self.ip_ranges.add(IPv4Network(ipn))

        # DNS as passed in manually
        if scan_dns:
            self.scan_dns = scan_dns if scan_dns else []

        # DNS as passed in by API
        elif scandns:
            self.scan_dns = scandns if scandns else []

        else:
            self.scan_dns = []

        # Scanner appliances as passed in manually
        if isinstance(scanner_appliances, list):
            self.scanner_appliances = [app for app in scanner_appliances]
 
        # Scanner appliances as passed in by API
        elif (isinstance(scanner_appliances, dict)
                and 'scanner_appliance' in scanner_appliances):
            self.scanner_appliances = [app for app in scanner_appliances
                                            ['scanner_appliance']]

        else:
            self.scanner_appliances = []

    @property
    def ip_addresses(self):
        """IP addresses in ranges."""
        ip_addresses = set()

        for ipn in self.ip_ranges:
            for ip in ipn:
                ip_addresses.add(ip)

        return ip_addresses

    @property
    def ip_range_strings(self):
        """IP ranges in dash-string format."""
        ranges = set()

        for ipn in self.ip_ranges:
            ranges.add('{0}-{1}'.format(ipn[0], ipn[-1]))

        return ranges

    def addAsset(self, conn, ip):
        """Add Asset to Asset Group."""
        call = '/api/2.0/fo/asset/group/'
        parameters = {'action': 'edit',
                      'id': self.id,
                      'add_ips': ip}

        conn.request(call, parameters)

        self.scan_ips.append(ip)
        
    def setAssets(self, conn, ips):
        """Add Assets to Asset Group."""
        call = '/api/2.0/fo/asset/group/'
        parameters = {'action': 'edit',
                      'id': self.id,
                      'set_ips': ips}

        conn.request(call, parameters)

        for ip in ips:
            self.scan_ips.append(ip)

    # PEP8 cleanup, preserved method names for backwards-compatibility
    add_asset = addAsset
    set_assets = setAssets
    add_assets = setAssets


class ReportTemplate(object):
    """Report Template."""

    def __init__(self, is_global=None, id=None, last_update=None,
                 template_type=None, title=None, type=None, user=None):
        """
        Initialize instance of ReportTemplate.

        Keyword Args:
            is_global (bool): Is global Report Template.
            id (int): ID.
            last_update (str): Last updated date.
            template_type (str): Template type.
            title (str): Report Template title.
            type (str): Report Template type.
            user (dict): Qualys User.
        """
        self.isGlobal = int(is_global)
        self.is_global = self.isGlobal
        self.id = int(id)
        self.template_type = template_type
        self.title = title
        self.type = type
        self.user = user.LOGIN
        self.last_update = dateutil.parser.parse(last_update) \
            if last_update else None


class Report(object):
    """Report."""
    def __init__(self, expiration_datetime, id,
                 launch_datetime, output_format, size,
                 status, type, user_login):
        """Initialize instance of Report."""
        self.id = int(id)
        self.output_format = output_format
        self.size = size
        self.status = status.STATE
        self.type = type
        self.user_login = user_login

        self.launch_datetime = dateutil.parser.parse(launch_datetime) \
            if launch_datetime else None
        
        self.expiration_datetime = dateutil.parser.parse(expiration_datetime) \
            if expiration_datetime else None

    def download(self, conn):
        """Download Report."""
        call = '/api/2.0/fo/report'
        parameters = {'action': 'fetch', 'id': self.id}

        if self.status == 'Finished':
            return conn.request(call, parameters)


class Scan(object):
    """Scan Job."""
    def __init__(self, asset_groups=[], duration=None, launch_datetime=None,
                 option_profile=None, processed=None, ref=None, status=None,
                 target=None, title=None, type=None, user_login=None,
                 **kwargs):
        """
        Initialize instance of Scan.

        Keyword Args:
            asset_groups (list): Asset groups.
            duration (str): Scan duration.
            launch_datetime (str): Launch datetime.
            option_profile (str): Option profile.
            processed (int): Processed status.
            ref (str): Reference.
            status (str): Scan status.
            target (str): Scan target.
            title (str): Scan title.
            type (str): Scan type.
            user_login (str): Username.
        """
        self.assetgroups = asset_groups
        self.duration = str(duration)
        self.option_profile = str(option_profile)
        self.processed = int(processed)
        self.ref = str(ref)
        self.status = str(status['state'])
        self.target = str(target).split(', ')
        self.title = str(title)
        self.type = str(type)
        self.user_login = str(user_login)
        self.launch_datetime = dateutil.parser.parse(launch_datetime) \
            if launch_datetime else None
        
    def cancel(self, conn):
        """Cancel scan."""

        # Raise exception if Scan is already cancelled or finished
        if any(self.status in s for s in ['Cancelled', 'Finished', 'Error']):
            err_msg = 'Scan cannot be cancelled because its status is {0}' \
                      .format(self.status)

            raise ValueError(err_msg)

        # Cancel Scan
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'cancel',
                        'scan_ref': self.ref}

        conn.request(call, parameters)

        parameters = {'action': 'list',
                      'scan_ref': self.ref,
                      'show_status': 1}

        self.status = \
            objectify.fromstring(conn.request(call, parameters)) \
                     .RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    def pause(self, conn):
        """Pause Scan."""

        # Raise Exception if Scan is not running
        if self.status != 'Running':
            err_msg = 'Scan cannot be paused because its status is {0}' \
                      .format(self.status)

            raise ValueError(err_msg)

        # Pause Scan
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'pause',
                        'scan_ref': self.ref}

        conn.request(call, parameters)
        
        parameters = {'action': 'list',
                      'scan_ref': self.ref,
                      'show_status': 1}

        self.status = \
            objectify.fromstring(conn.request(call, parameters)) \
                     .RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    def resume(self, conn):
        """Resume Scan."""

        # Raise Exception if Scan is not paused
        if self.status != 'Paused':
            err_msg = 'Scan cannot be cancelled because its status is {0}' \
                      .format(self.status)

        # Resume Scan
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'resume',
                        'scan_ref': self.ref}

        conn.request(call, parameters)
        
        parameters = {'action': 'list',
                      'scan_ref': self.ref,
                      'show_status': 1}

        self.status = \
            objectify.fromstring(conn.request(call, parameters)) \
                     .RESPONSE.SCAN_LIST.SCAN.STATUS.STATE