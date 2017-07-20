from __future__ import absolute_import
import datetime
import xmltodict
from lxml import objectify

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

        last_scan = last_vuln_scan_datetime

        if isinstance(last_scan, str):
            last_scan = str(last_scan).replace('T', ' ') \
                                      .replace('Z', '') \
                                      .split(' ')

            date = last_scan[0].split('-')
            time = last_scan[1].split(':')

            self.last_scan = datetime.datetime(int(date[0]),
                                               int(date[1]),
                                               int(date[2]),
                                               int(time[0]),
                                               int(time[1]),
                                               int(time[2]))
        else:
            self.last_scan = None

        self.netbios = netbios
        self.os = os
        self.tracking_method = tracking_method

class AssetGroup(object):
    def __init__(self, business_impact, id, last_update, scanips, scandns, scanner_appliances, title):
        self.business_impact = str(business_impact)
        self.id = int(id)
        self.last_update = str(last_update)
        self.scanips = scanips
        self.scandns = scandns
        self.scanner_appliances = scanner_appliances
        self.title = str(title)
        
    def addAsset(conn, ip):
        call = '/api/2.0/fo/asset/group/'
        parameters = {'action': 'edit', 'id': self.id, 'add_ips': ip}
        conn.request(call, parameters)
        self.scanips.append(ip)
        
    def setAssets(conn, ips):
        call = '/api/2.0/fo/asset/group/'
        parameters = {'action': 'edit', 'id': self.id, 'set_ips': ips}
        conn.request(call, parameters)
        
class ReportTemplate(object):
    def __init__(self, isGlobal, id, last_update, template_type, title, type, user):
        self.isGlobal = int(isGlobal)
        self.id = int(id)
        self.last_update = str(last_update).replace('T', ' ').replace('Z', '').split(' ')
        self.template_type = template_type
        self.title = title
        self.type = type
        self.user = user.LOGIN
        
class Report(object):
    def __init__(self, expiration_datetime, id, launch_datetime, output_format, size, status, type, user_login):
        self.expiration_datetime = str(expiration_datetime).replace('T', ' ').replace('Z', '').split(' ')
        self.id = int(id)
        self.launch_datetime = str(launch_datetime).replace('T', ' ').replace('Z', '').split(' ')
        self.output_format = output_format
        self.size = size
        self.status = status.STATE
        self.type = type
        self.user_login = user_login
        
    def download(self, conn):
        call = '/api/2.0/fo/report'
        parameters = {'action': 'fetch', 'id': self.id}
        if self.status == 'Finished':
            return conn.request(call, parameters)
        
class Scan(object):
    """Scan job."""
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

        launch_datetime = str(launch_datetime).replace('T', ' ') \
                                              .replace('Z', '') \
                                              .split(' ')
        date = launch_datetime[0].split('-')
        time = launch_datetime[1].split(':')

        self.launch_datetime = datetime.datetime(int(date[0]),
                                                 int(date[1]),
                                                 int(date[2]),
                                                 int(time[0]),
                                                 int(time[1]),
                                                 int(time[2]))
        self.option_profile = str(option_profile)
        self.processed = int(processed)
        self.ref = str(ref)
        self.status = str(status['state'])
        self.target = str(target).split(', ')
        self.title = str(title)
        self.type = str(type)
        self.user_login = str(user_login)
        
    # def cancel(self, conn):
    #     """Cancel scan."""
    #     cancelled_statuses = ['Cancelled', 'Finished', 'Error']

    #     if any(self.status in s for s in cancelled_statuses):
    #         err_msg = 'Scan cannot be cancelled because its status is {0}' \
    #                   .format(self.status)

    #         raise ValueError(err_msg)

    #     else:
    #         call = '/api/2.0/fo/scan/'
    #         parameters = {'action': 'cancel', 'scan_ref': self.ref}
    #         conn.request(call, parameters)
            
    #         parameters = {'action': 'list', 'scan_ref': self.ref, 'show_status': 1}
    #         self.status = objectify.fromstring(conn.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    # def pause(self, conn):
    #     if self.status != "Running":
    #         raise ValueError("Scan cannot be paused because its status is "+self.status)
    #     else:
    #         call = '/api/2.0/fo/scan/'
    #         parameters = {'action': 'pause', 'scan_ref': self.ref}
    #         conn.request(call, parameters)
            
    #         parameters = {'action': 'list', 'scan_ref': self.ref, 'show_status': 1}
    #         self.status = objectify.fromstring(conn.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE
            
    # def resume(self, conn):
    #     if self.status != "Paused":
    #         raise ValueError("Scan cannot be resumed because its status is "+self.status)
    #     else:
    #         call = '/api/2.0/fo/scan/'
    #         parameters = {'action': 'resume', 'scan_ref': self.ref}
    #         conn.request(call, parameters)
            
    #         parameters = {'action': 'list', 'scan_ref': self.ref, 'show_status': 1}
    #         self.status = objectify.fromstring(conn.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE