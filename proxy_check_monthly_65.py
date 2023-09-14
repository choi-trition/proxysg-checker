import requests as rq
import re
import urllib3
import sys
import io
import os
import time
import getpass as pw

sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding = 'utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding = 'utf-8')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

wd = os.path.dirname(os.path.realpath(__file__))
os.chdir(wd)

ct = time.strftime('%Y.%m.%d %a %H:%M UTC%z', time.localtime())
gmt = time.strftime('%a %b %d, %Y %H', time.gmtime(time.time()))
cd = time.strftime('%m%d', time.localtime())

ver_info = []
health = []
hardware = []
disk = []
http = []
tcp = []
bcwf = []
statistics = []

prompt = '''
---------------ProxySG Checker---------------

 1. Check ProxySG

 2. Test Internet connection via ProxySG

 3. Test ProxySG Categorization

 4. Monthly Check

 5. Quit

---------------------------------------------

 Please select number: '''


info_flag = 0
menu = 0
appliance = 0
hostname_list = []
hostname = ''

def base_info():
    global info_flag, menu, appliance, hostname, hostname_list
    if info_flag == 0:
        info_flag = 1
        print('\nPlease input the ProxySG information.\n')
        try:
            username = str(input('Console account username\texample) administrator\n : '))
            password = str(pw.getpass('Console account password\texample) mypassword\n : '))
            auth = (username, password)
            appliance = int(input('How many appliances do you want to check ?\texample) 3\n : '))
            if appliance == 1:
                hostname = str(input('Hostname\texample) Proxy_1\n : '))
                proxy_ip = str(input('Proxy IP\texample) 192.168.1.100\n : '))
            elif appliance > 1:
                print('\nPlease make sure the data had written in correct format.\nFormat >> Hostname : ProxyIP\n\nexample)\nProxy_1 : 192.168.1.100\nProxy_2 : 192.168.1.200\nProxy_3 : 192.168.1.300\n...\n''')
                list_file = str(input('What is the ProxySG-List file name ?\texample) myProxyList.txt\n : '))
                hostname_list = []
                proxy_ip_list = []
                file = open(list_file, 'r')
                while True:
                    line = file.readline()
                    if not line: break
                    data = line.strip().split(' : ')
                    hostname_list.append(data[0])
                    proxy_ip_list.append(data[1])
                file.close()
        except ValueError:
            print('\nPlease input correct value.\n', flush=True)
            time.sleep(1)
            exit()
        else:
            pass
    else: pass

    def make_section():
        ver_info.clear()
        health.clear()
        hardware.clear()
        disk.clear()
        http.clear()
        tcp.clear()
        bcwf.clear()
        statistics.clear()
        sysinfoUrl = 'https://'+proxy_ip+':8082/sysinfo'
        try:
            sysinfo_get = rq.get(sysinfoUrl, verify = False, auth = auth)
        except:
            print(' Can not connect to the '+hostname+'. Please check the IP or your network.\n', flush=True)
            time.sleep(1.5)
            exit()
        else:
            lines = sysinfo_get.iter_lines(decode_unicode=True)

            # # 섹셔닝--------
            section_line = re.compile('__________________________________________________________________________')
            subject_name = ('Version Information', 'Health Monitor', 'Hardware sensors', 'Storage Disk Statistics', 'HTTP Main', 'TCP/IP Statistics', 'Content Filter Status', 'Persistent Statistics')
            subject1 = re.compile(subject_name[0])
            subject2 = re.compile(subject_name[1])
            subject3 = re.compile(subject_name[2])
            subject4 = re.compile(subject_name[3])
            subject5 = re.compile(subject_name[4])
            subject6 = re.compile(subject_name[5])
            subject7 = re.compile(subject_name[6])
            subject8 = re.compile(subject_name[7])
            subject_write = 0

            # Make Section Lists
            for line in lines:
                line = line.strip()
                if section_line.search(line):
                    next(lines)
                    line = next(lines)
                    if subject1.search(line):
                        subject_write = 1
                    elif subject2.search(line):
                        subject_write = 2
                    elif subject3.search(line):
                        subject_write = 3
                    elif subject4.search(line):
                        subject_write = 4
                    elif subject5.search(line):
                        subject_write = 5
                    elif subject6.search(line):
                        subject_write = 6
                    elif subject7.search(line):
                        subject_write = 7
                    elif subject8.search(line):
                        subject_write = 8
                    else:
                        subject_write = 0
                if subject_write == 1:
                    ver_info.append(line)
                elif subject_write == 2:
                    health.append(line)
                elif subject_write == 3:
                    hardware.append(line)
                elif subject_write == 4:
                    disk.append(line)
                elif subject_write == 5:
                    http.append(line)
                elif subject_write == 6:
                    tcp.append(line)
                elif subject_write == 7:
                    bcwf.append(line)
                elif subject_write == 8:
                    statistics.append(line)


    def sysinfo_check():
        print('\n========================Start '+hostname+' Checking...========================\n')
        print('Excution Time: '+ct+'\n')

        # -- version info checking
        print('[Version Information]\n', ver_info[3], '\n', ver_info[4],'\n')
        print('[Uptime]\n', ver_info[7].replace('The ProxySG Appliance', hostname), '\n', ver_info[8].replace('The ProxySG Appliance', hostname),'\n')

        # -- utilization checking
        hw_rsc = ('Stat: CPU Utilization', 'Stat: Memory Utilization', 'Stat: Interface')
        print('[Resource Utilization]')
        for i in hw_rsc:
            srch = re.compile(i)
            for idx, data in enumerate(health):
                if srch.search(data):
                    name = data.split(': ')
                    value = health[idx+3].split(': ')
                    print (' '+name[1]+'\t----- '+value[1]+' %')
                else: continue
        print()

        # -- overall health checking
        health_flag = 0
        overall_health = re.compile('Overall Health')
        ok_status = 'Current State                 : OK'
        storage_stat = re.compile(r'Storage[\d]{1}00[.]5[.][5-9][.]1')
        print('[Overall Health]\n Checking List: CPU, Memory, Disk, Hardware Sensors, License')
        for idx, data in enumerate(health):
            if overall_health.search(data):
                if health[idx+1] == ok_status:
                    print(' ..... Every Component is OK\n')
                    health_flag = 1
                else:
                    print("\n !!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!!WARNING!!")
                    print(" !!WARNING!! One or More Component is NOT ok !!!WARNING!!")
                    print(" !!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!!WARNING!!\n")
                    print(" Please check 'Health Monitor' and 'Hardware sensors' part in the "+hostname+"_check.txt file!!\n")
                    make_txt(health)
                    make_txt(hardware)
                    health_flag = 1
            else:
                if health_flag == 1: break


        # -- disk read / write error checking
        for data in disk:
            if storage_stat.search(data):
                disk_info = data.split()
                if disk_info[1] == '00000000:00000000': pass
                else:
                    make_txt(disk)
                    print('Disk Read/Write Error is occurring. Please contact your Proxy Engineer.\n')
            else: continue

        # -- concurrent users and tcp connections
        print('[Current Users, TCP Connections]')
        c_users = re.compile('users:current~hourly')

        for data in statistics:
            if c_users.search(data):
                c_users_value = data.split('): ')
                c_users_value_list = c_users_value[1].split()
                c_users_list = list(map(int, c_users_value_list))
                print(' Current Users:',c_users_list[-1])
            else: continue

        est_conn = re.compile('TCP1.201')
        # que_conn = re.compile('TCP1.203')

        for data in tcp:
            if est_conn.search(data):
                est_conn_list = data.split()
                print(' Current Established TCP Connections:',est_conn_list[1])
            # if que_conn.search(data):
            #     que_conn_list = data.split()
            #     print(' Current Queued TCP Connections:',que_conn_list[1])
        print()

        # -- daily traffic
        print('[Traffic Overview (Last 24 hours)]')
        http_c = re.compile('svc:proxy:HTTP:intercepted_client_bytes~daily15minute')
        http_s = re.compile('svc:proxy:HTTP:intercepted_server_bytes~daily15minute')
        https_c = re.compile('svc:proxy:HTTPS Forward Proxy:intercepted_client_bytes~daily15minute')
        https_s = re.compile('svc:proxy:HTTPS Forward Proxy:intercepted_server_bytes~daily15minute')
        ssl_c = re.compile('svc:proxy:SSL:intercepted_client_bytes~daily15minute')
        ssl_s = re.compile('svc:proxy:SSL:intercepted_server_bytes~daily15minute')

        def to_mbps(value):
            mbps = value*8/900/1024/1024
            return mbps

        def t_value_listing(value):
            t_list_1 = value.split('): ')
            t_vlaue_list_2 = t_list_1[1].split()
            t_list = list(map(int, t_vlaue_list_2))
            return t_list

        def traffic_print(subject, value_list):
            max_value = to_mbps(max(value_list))
            average = to_mbps(sum(value_list)/len(value_list))
            print(f' {subject}' + ':\tMax %.2f Mbps, '%max_value + 'Average %.2f Mbps'%average)

        for data in statistics:
            if http_c.search(data):
                http_c_list = t_value_listing(data)
                traffic_print('HTTP Client Traffic', http_c_list)
            elif http_s.search(data):
                http_s_list = t_value_listing(data)
                traffic_print('HTTP Server Traffic', http_s_list)
            elif https_c.search(data):
                https_c_list = t_value_listing(data)
                traffic_print('HTTPS Client Traffic', https_c_list)
            elif https_s.search(data):
                https_s_list = t_value_listing(data)
                traffic_print('HTTPS Server Traffic', https_s_list)
            elif ssl_c.search(data):
                ssl_c_list = t_value_listing(data)
                traffic_print('SSL Client Traffic', ssl_c_list)
            elif ssl_s.search(data):
                ssl_s_list = t_value_listing(data)
                traffic_print('SSL Server Traffic', ssl_s_list)
            else: continue
        print()

        # -- bcwf db update check
        print('[BCWF DB Update]')
        web_bcwf = rq.get('https://'+proxy_ip+':8082/ContentFilter/Blue%20Coat/Log', verify = False, auth = auth)
        bcwf_list = web_bcwf.text.splitlines()
        bcwf_date = re.compile('Database date:')
        bcwf_expire = re.compile('Database expires:')
        bcwf_version = re.compile('Database version:')

        for data in bcwf_list:
            if bcwf_date.search(data):
                print(f' {data.strip()}')
            elif bcwf_expire.search(data):
                print(f' {data.strip()}')
            elif bcwf_version.search(data):
                print(f' {data.strip()}')
            else: continue
        print()

        integration_health()
        print('\n============================Checking Done!!===========================\n')           


    def monthly_check():
        print('\n===================Start '+hostname+' Monthly Checking...===================\n')
        print('Reported Time: '+ct+'\n')
        print('[Version Information]\n', ver_info[3], '\n', ver_info[-3],'\n')
        print('[Uptime]\n', ver_info[7].replace('The ProxySG Appliance was last ', ''), '\n', ver_info[8].replace('The ProxySG Appliance was last ', ''),'\n')
        
        def t_listing(value):
            t_value_list2 = []
            for i in statistics:
                if value.search(i):
                    t_list_1 = i.split('): ')
                    t_value_list2 = t_list_1[1].split()
                    t_list = list(map(int, t_value_list2))
                    break
                else: continue
            return t_list

        syst = ver_info[6][20:39]
        print('[System Time]')
        print(' Current ProxySG Time:',ver_info[6][20:])
        if syst == gmt:
            print(' System Time is OK\n')
        else:
            print(' System Time is 1 or more hours diffrent from current time!\n Please check System Time!\n')


        # -- utilization checking
        hw_rsc = ('Stat: CPU Utilization', 'Stat: Memory Utilization', 'Stat: Interface', r'Stat: CPU (\d{1} )?temperature', 'Stat: System center temperature','Stat: Motherboard temperature')
        print('[Current Utilization]')
        for i in hw_rsc:
            srch = re.compile(i)
            for idx, data in enumerate(health):
                if srch.search(data):
                    name = data.split(': ')
                    value = health[idx+3].split(': ')
                    print (' '+name[1]+'\t----- '+value[1])
                else: continue

        cpu_g = re.compile('system:cpu-usage~yearly')
        mem_g = re.compile('system:memory-usage~yearly')

        cpu_g_list = t_listing(cpu_g)
        mem_g_list = t_listing(mem_g)
        cpu_g_av = sum(cpu_g_list[-4:])/4
        mem_g_av = sum(mem_g_list[-4:])/4
        print(' CPU Growth\t----- %.0f'%cpu_g_av, cpu_g_list[-4:])
        print(' Memory Growth\t----- %.0f'%mem_g_av, mem_g_list[-4:])
        print()

        # -- overall health checking
        health_flag = 0
        overall_health = re.compile('Overall Health')
        ok_status = 'Current State                 : OK'
        print('[Overall Health]\n Checking List: CPU, Memory, Disk, Hardware Sensors, Health Check, License\n')
        for idx, data in enumerate(health):
            if overall_health.search(data):
                if health[idx+1] == ok_status:
                    print(' ..... Every Component is OK\n')
                    health_flag = 1
                else:
                    print(" One or more component is NOT oK!\n Please check 'Health Monitor' and 'Hardware sensors' part in the "+hostname+"_check.txt file!!\n")
                    make_txt(health)
                    make_txt(hardware)
                    health_flag = 1
            else:
                if health_flag == 1: break


        # -- disk read / write error checking
        storage_stat = re.compile(r'Storage[\d]{1}00[.]5[.][5-9][.]1')
        print('[Disk Error]')
        for data in disk:
            if storage_stat.search(data):
                disk_info = data.split()
                if disk_info[1] == '00000000:00000000':
                    print(' %.8s\t----- OK'%disk_info[0])
                    continue
                else:
                    make_txt(disk)
                    print(' Disk Read/Write Error is occurring.\n'+data)
            else: continue
        print()
        # -- concurrent users and tcp connections
        print('[Users]')
        c_users = re.compile('users:current~hourly')

        for data in statistics:
            if c_users.search(data):
                c_users_value = data.split('): ')
                c_users_value_list = c_users_value[1].split()
                c_users_list = list(map(int, c_users_value_list))
                print(' User Month:',sum(c_users_list[-4:])/4,'\n')
                break
            else: continue

        print('[TCP]')
        est_conn = re.compile('TCP1.201')
        # que_conn = re.compile('TCP1.203')

        for data in tcp:
            if est_conn.search(data):
                est_conn_list = data.split()
                print(' Current Established TCP Connections:',est_conn_list[1])
                break
            # if que_conn.search(data):
            #     que_conn_list = data.split()
            #     print(' Current Queued TCP Connections:',que_conn_list[1])
        print()


        # -- daily traffic
        print('[Saving]')
        saving_c = re.compile('http:client-bytes~yearly')
        saving_s = re.compile('http:server-bytes~yearly')
        
        c_saving_list = t_listing(saving_c)
        s_saving_list = t_listing(saving_s)

        try:
            saving = (sum(c_saving_list[-4:]) - sum(s_saving_list[-4:])) / sum(c_saving_list[-4:]) * 100
        except:
            print(' Not enough data for calculation.')
        else:
            print(' Saving: %.2f %%'%saving)
        print()

        # -- bcwf db update check
        print('[BCWF DB Update]')
        web_bcwf = rq.get('https://'+proxy_ip+':8082/ContentFilter/Blue%20Coat/Log', verify = False, auth = auth)
        bcwf_list = web_bcwf.text.splitlines()
        bcwf_date = re.compile('Database date:')
        bcwf_expire = re.compile('Database expires:')
        bcwf_version = re.compile('Database version:')

        for data in bcwf_list:
            if bcwf_date.search(data):
                print(f' {data.strip()}')
            elif bcwf_expire.search(data):
                print(f' {data.strip()}')
            elif bcwf_version.search(data):
                print(f' {data.strip()}')
            else: continue
        print()
        
        print('[Interface CRC]')
        in_err = re.compile(r'tcpip:interface:\d{1}:\d{1}:input-errors~monthly')
        out_err = re.compile(r'tcpip:interface:\d{1}:\d{1}:output-errors~monthly')
        
        def crc_check(srch):
            err_list = []
            for data in statistics:
                if srch.search(data):
                    err_list1 = data.split('): ')
                    err_list2 = err_list1[1].split()
                    for i in err_list2:
                        err_list.append(i)
                        err_list = list(map(int, err_list))
                else: continue
            return err_list

        in_err_list = crc_check(in_err)
        out_err_list = crc_check(out_err)

        if sum(in_err_list) + sum(out_err_list) == 0:
            print(' CRC is OK')
        else:
            print(' CRC Error had occurred. Please check it.')
        print()

        print('[HTTP Worker]')
        worker = re.compile('HTTP_MAIN_0103')
        limit = re.compile('HTTP_MAIN_0090')
        http_flag = 0

        for data in http:
            if http_flag == 2: break
            elif worker.search(data):
                http_worker = data.split()
                print(' Highwater:',http_worker[1])
                http_flag += 1
            elif limit.search(data):
                limit_worker = data.split()
                print(' Worker Limit:',limit_worker[1])
            else: continue
        
        print()

        integration_health()
        print('\n============================Checking Done!!===========================\n')


    def make_txt(section_list):
        try:
            os.makedirs(cd+'_ProxyCheck', exist_ok=True)
            file = open(cd+'_ProxyCheck\\'+hostname+'_check.txt', 'a', encoding='utf-8')
        except PermissionError:
            print("\n\t[ERROR] Can not write the 'ProxyCheck.txt' file.\t-Permission Error\n")
        except:
            print("\n\tOops.. ProxyChecker can not make file.\n")
        else:
            for i in section_list:
                file.write(i+'\n')
            file.write('\n==============================================================================\n\n')
            file.close()


    def integration_health():
        # # 헬스체크 URL
        try:    
            healthcheck = rq.get('https://'+proxy_ip+':8082/health_check/statistics', verify = False, auth = auth)
        except:
            print(' Can not connect to the '+hostname+'. Please check the IP or your network.\n', flush=True)
            time.sleep(1.5)
            exit()
        else:
            health_status = healthcheck.text
            health = health_status.splitlines()

            keyword = {'Authentication':3, 'DNS Server':3, 'Forwarding':4, 'External Services':3, 'Content analysis services':3}
            unused = re.compile('Disabled: Healthy')
            okup = re.compile('Enabled  	OK  	UP')
            unup = re.compile('Enabled  	Unknown  	UP')
            drtr = re.compile('drtr.rating_service')

            print('[Health Check]')

            for data in keyword.keys():
                check = re.compile(data)
                for idx, line in enumerate(health):
                    if check.search(line):
                        # print(health[idx+2].strip())    # health check object
                        # print(health[idx+keyword[data]].strip())  # health check status
                        if data == 'External Services':
                            if drtr.search(health[idx+2]):
                                if unused.search(health[idx+4]):
                                    print(' '+health[idx+2].strip()+' \t\t[OK] (Health-check Unused)')
                                    continue
                                elif okup.search(health[idx+4]):
                                    print(' '+health[idx+2].strip()+' \t\t[OK]')
                                    continue
                                elif unup.search(health[idx+4]):
                                    print(' '+health[idx+2].strip()+' \t\t[OK]')
                                    continue
                                else: 
                                    print(' '+health[idx+2].strip()+' \t\t[NG] Please check this component!')
                                    continue
                            else: pass
                        if unused.search(health[idx+keyword[data]]):
                            print(' '+health[idx+2].strip()+' \t\t[OK] (Health-check Unused)')
                        elif okup.search(health[idx+keyword[data]]):
                            print(' '+health[idx+2].strip()+' \t\t[OK]')
                        elif unup.search(health[idx+keyword[data]]):
                            print(' '+health[idx+2].strip()+' \t\t[OK]')
                        else: print(' '+health[idx+2].strip()+' \t\t[NG] Please check this component!')
                    else: continue
            print()


    def get_test():
        # Proxy - internet 접속 테스트
        print('\n================Start '+hostname+' Internet Connection Test...================\n')
        proxyDict = {'http':'http://'+proxy_ip+':8080', 'https':'https://'+proxy_ip+':8080'}
        print('[Proxy Internet Connection Test]\n Test URL:\t'+get_url+'\n')
        print(' NOTE: This function does NOT offer authentication method.\n If your ProxySG need authentication, please find another way to check for test.\n')
        try:
            get_result = rq.get(get_url, verify = False, proxies=proxyDict)
        except rq.exceptions.MissingSchema:
            print(' Please input the URL correctly.\n example) http://www.example.com\n')
        except:
            print(" ProxySG can't connect to the '"+get_url+"'.\n Please test with web browser for details.\n")
        else:
            if get_result.ok: print(" Proxy connected to the '"+get_url+"' successfully.\n")
            else: print(" Proxy is unable to connect to the '"+get_url+"'.\n Please test with web browser for details.\n")
        print('\n====================================Done!!===================================\n')


    def category_test():
        # # Proxy - categorization 테스트
        print('\n===================Start '+hostname+' Categorization Test...==================\n')
        print('[Category Check]')
        print(' Test URL: '+category_url+'\n')
        try:
            category = rq.get('https://'+proxy_ip+':8082/ContentFilter/TestUrl/'+category_url, verify = False, auth = auth)
        except:
            print(' Can not connect to the '+hostname+'. Please check the IP or your network.\n', flush=True)
            time.sleep(1.5)
        else:
            category_list = category.text.splitlines()
            for data in category_list:
                print(f' {data.strip()}')
        print('\n====================================Done!!===================================\n')


    def choice_menu():
        global appliance, hostname, hostname_list
        nonlocal proxy_ip
        if menu == 1:
            if appliance == 1:
                make_section()
                sysinfo_check()
            elif appliance > 1:
                for i in range(appliance):
                    hostname = str(hostname_list[i])
                    proxy_ip = str(proxy_ip_list[i])
                    make_section()
                    sysinfo_check()
        elif menu == 2:
            if appliance == 1:
                get_test()
            elif appliance > 1:
                for i in range(appliance):
                    hostname = hostname_list[i]
                    proxy_ip = proxy_ip_list[i]
                    get_test()
        elif menu == 3:
            if appliance == 1:
                category_test()
            elif appliance > 1:
                for i in range(appliance):
                    hostname = hostname_list[i]
                    proxy_ip = proxy_ip_list[i]
                    category_test()
        elif menu == 4:
            if appliance == 1:
                make_section()
                monthly_check()
            elif appliance > 1:
                for i in range(appliance):
                    hostname = str(hostname_list[i])
                    proxy_ip = str(proxy_ip_list[i])
                    make_section()
                    monthly_check()
        else: pass

    return choice_menu

if __name__ == "__main__":
    while True:
        print(prompt, end='')
        try:
            number = int(input())
            menu = number
        except ValueError as e:
            msg = str(e).split(':')
            if msg[1] == " 'nene'":
                print("\nchicken chicken!!\n퇴근하자 이녀석들아!!\n", flush=True)
                time.sleep(1)
                exit()
            else: print('\nPlease type the correct number.\n')
        except:
            print('\nPlease type the correct number.\n')
        else:
            if number == 1:
                if info_flag == 0:
                    check_start = base_info()
                else:
                    if appliance > 1:
                        print('\nCurrent ProxySG applianes set\n\t',hostname_list,'\n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                    else:
                        print('\nCurrent ProxySG applianes set\n\t ['+hostname+'] \n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                txtwrite = str(input('Would you like to export the result to text file? (y/n)\n : '))
                if txtwrite == 'y' or txtwrite == 'yes':
                    print('\nGetting ProxySG sysinfo...\n',flush=True)
                    stdout = sys.stdout
                    filename = cd+'_CheckResult.txt'
                    file = open(filename, 'a', encoding='utf-8')
                    sys.stdout = file
                    check_start()
                    file.close()
                    sys.stdout = stdout
                    print('\nDone!!\n')           
                else:
                    print('\nGetting ProxySG sysinfo...\n',flush=True)
                    check_start()
            elif number == 2:
                if info_flag == 0:
                    check_start = base_info()
                else:
                    if appliance > 1:
                        print('\nCurrent ProxySG applianes set\n\t',hostname_list,'\n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                    else:
                        print('\nCurrent ProxySG applianes set\n\t ['+hostname+'] \n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                get_url = str(input('\nInternet Connection test URL\n example) http://www.example.com\n : '))
                check_start()
            elif number == 3:
                if info_flag == 0:
                    check_start = base_info()
                else:
                    if appliance > 1:
                        print('\nCurrent ProxySG applianes set\n\t',hostname_list,'\n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                    else:
                        print('\nCurrent ProxySG applianes set\n\t ['+hostname+'] \n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                category_url = str(input('\nCategorization test URL\n example) mail.example.com\n : '))
                check_start()
            if number == 4:
                if info_flag == 0:
                    check_start = base_info()
                else:
                    if appliance > 1:
                        print('\nCurrent ProxySG applianes set\n\t',hostname_list,'\n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                    else:
                        print('\nCurrent ProxySG applianes set\n\t ['+hostname+'] \n')
                        change_info = str(input('Would you like to check other ProxySG? (y/n)\n : '))
                        if change_info == 'y' or change_info == 'yes':
                            info_flag = 0
                            check_start = base_info()
                            pass
                txtwrite = str(input('Would you like to export the result to text file? (y/n)\n : '))
                if txtwrite == 'y' or txtwrite == 'yes':
                    print('\nGetting ProxySG sysinfo...\n',flush=True)
                    stdout = sys.stdout
                    filename = cd+'_MonthlyCheck.txt'
                    file = open(filename, 'a', encoding='utf-8')
                    sys.stdout = file
                    check_start()
                    file.close()
                    sys.stdout = stdout
                    print('\nDone!!\n')           
                else:
                    print('\nGetting ProxySG sysinfo...\n',flush=True)
                    check_start()
            elif number == 5:
                print('\n Byebye~ Have a nice day! -from Choi\n', flush=True)
                time.sleep(1)
                exit()
            elif number <1 or number > 4: print('\nPlease type the correct number.\n')
