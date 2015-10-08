f=open('auth.log')
time=[]
ip=[]
reason=[]
r=0
ff=open('block.txt')
l=[]
sub=[]
bip=[]
for li in ff:
    if li[0]!='#' and li[0].isdigit():
        s=li.find('\t')
        l.append(li[:s])
        li=li[s+1:]
        s=li.find('\t')
        li=li[s+1:]
        s=li.find('\t')
        sub.append(li[:s])
for a in range(len(l)):
    if sub[a]=='24':
        for i in range(1,255):
            e=str(l[a])
            ipp=e[:-1]+str(i)
            bip.append(ipp)
    if sub[a]=='16':
        for i in range(1,255):
            e=str(l[a])
            ipp=e[:-3]+str(i)
            for ii in range(1,255):
                ipp=ipp+'.'+str(ii)
                bip.append(ipp)
    if sub[a]=='8':
        for i in range(1,255):
            e=str(l[a])
            ipp=e[:-5]+str(i)
            for ii in range(1,255):
                ippp=ipp+'.'+str(ii)
                for iii in range(1,255):
                    ipppp=ippp+'.'+str(iii)
                    bip.append(ipppp)
for line in f:
    time.append(line[:15])
    st=line.find('ip')
    ed=line.find('sshd')
    ip.append(line[st+3:ed])
    re=line.find(']: ')
    reason.append(line[re+3:])    
    r=r+1
ispp=[]
ivuser=[]
ke=[]
ist=0
t=0
tt=0
danger=""
le=len(time)
for a in range(le):
    if 'reverse mapping checking getaddrinfo for' in reason[a]:
        lo=reason[a].find('reverse mapping checking getaddrinfo for ')
        le=reason[a].find('failed - POSSIBLE BREAK-IN ATTEMPT!')
        ispp.insert(ist,[reason[a][lo+40:le],ip[a],time[a]])
        ist=ist+1
    if 'error: Could not load host key: /etc/ssh/' in reason[a]:
        lo=reason[a].find('error: Could not load host key: /etc/ssh/')
        ke.insert(t,[ip[a],time[a]])
        t=t+1
    if 'Invalid user' in reason[a]:
        iv=reason[a].find('Invalid user')
        ie=reason[a].find('from')
        ivuser.insert(tt,[reason[a][iv+13:ie-1],reason[a][ie+5:],time[a]])
        tt=tt+1
print('#############Linux Auth Log Audit##############\n')
print('Enter 1 to know invalid user')
print('Enter 2 to know IP who attempt to login without key')
print('Enter 3 to know the  ISP name of Unauthorise access')

user=raw_input('\nEnter the number :')
if user=='1':
    for a in range(len(ivuser)):
        for b in range(len(bip)):
            if ivuser[a][0]==bip[b]:
                danger="TRUE"
        if danger=="TRUE":
            print 'Dangerous IP recognize. Source:DShield.org\n'
            print 'User was :'+ivuser[a][0]+' And IP was :'+ivuser[a][1]+' at time :'+ivuser[a][2]+'\n'
        else:
            print 'User was :'+ivuser[a][0]+' And IP was :'+ivuser[a][1]+' at time :'+ivuser[a][2]
        
if user=='2':
    for a in range(len(ke)):
        for b in range(len(bip)):
            if ivuser[a][0]==bip[b]:
                danger="TRUE"
        if danger=="TRUE":
            print 'Dangerous IP recognize. source:DShield.org\n'
            print 'IP was :'+ke[a][0]+' at time :'+ke[a][1]+'\n'
        else:
            print 'IP was :'+ke[a][0]+' at time :'+ke[a][1]
if user=='3':
    for a in range(len(ke)):
        for b in range(len(bip)):
            if ivuser[a][0]==bip[b]:
                danger="TRUE"
        if danger=="TRUE":
            print 'Dangerous IP recognize. Source:DShield.org\n'
            print 'IP '+ispp[a][0]+' And ISP is'+ispp[a][1]+' at time :'+ispp[a][2]+'\n'
        else:
            print 'IP '+ispp[a][0]+' And ISP is'+ispp[a][1]+' at time :'+ispp[a][2]
