from flask import Blueprint, redirect, render_template, request, url_for, session
from datetime import datetime
from App.models import db, User_id_name_pwd, User_XP, User_info, Post_id_restime, Post_info, PUM_pid_mid, PUM_info, FB_info
from utils.ch_login import is_login
import pandas as pd
from sqlalchemy import func

#修改昵称、密码、查看个人留言（含帖子1L），搜索全站帖子（可删帖）

user_blueprint = Blueprint('user', __name__)

@user_blueprint.route('/')
def hello_tom():
    return 'hello,January 2020!'

def find_fbid_by_name(fbtheme):
    return FB_info.query.filter_by(fb_theme=fbtheme).first().fb_id

def find_uid_by_name(username):
    return User_id_name_pwd.query.filter_by(u_name=username).first().u_id

def find_user_by_name(username):
    return User_id_name_pwd.query.filter_by(u_name=username).first()

def find_post_by_pid(pid):
    return Post_id_restime.query.filter_by(p_id=pid).first()

def add_user_to_db(uid,name,pwd,XP,grant):
    newuser1 = User_id_name_pwd(name = name, pwd=pwd)
    newuser1.u_id=uid
    newuser1.save()
    
    newuser2 = User_XP(uid = uid, XP=XP)
    newuser2.save()
    newuser1.u_XP.append(newuser2)
    
    newuser3 = User_info(uid = uid, grant=grant)
    newuser3.save()
    newuser1.u_info.append(newuser3)

@user_blueprint.route('/create_db/')
def create_db():
    """
    创建数据
    """
    print('begin create db')
    
    db.create_all()
    
    def init_data():
        datafile = 'F:\\code\\DBcourse\\finalhw\\myhw\\App\\dataset.csv'
        
        csv_data = pd.read_csv(datafile,encoding = 'utf-8',error_bad_lines=False)
        print(csv_data.shape)
        rowc = 0
        
        usercount=1
        userlist = []
        fblist = []
        userXP = {}
        
        #管理员
        admin1 = User_id_name_pwd(name = 'admin', pwd='123456')
        admin1.save()
        
        tmpuid = find_uid_by_name('admin')
        
        admin2 = User_XP(uid = tmpuid, XP=10000)
        admin2.save()
    
        admin3 = User_info(uid = tmpuid, grant=4)
        admin3.save()
        tmppid = 0
        tmpmid = 0
        for index, row in csv_data.iterrows():
            rowc+=1
            fb = row["category"]
            username = row["screenname"]
            content = row["text"]
            pos = content.find('http')
            content = content[:pos]
            
            if(fb not in fblist):
                fblist.append(fb)
                newfb = FB_info(theme = fb)
                newfb.save()
            
            if(username not in userlist):
                usercount+=1
                userlist.append(username)
                userXP[username]=50
                add_user_to_db(usercount,username,'123456',userXP[username],2)
            else:
                userXP[username]+=10
            
            if(rowc%2==0):
                #print('rowc:'+str(rowc))
                continue
            
            tmpuser = User_id_name_pwd.query.filter_by(u_name=username).first()
            
            if((rowc-1)%10 == 0):    
                #print((rowc//10)+1)
                newpost = Post_info(uid = tmpuser.u_id,fbid = find_fbid_by_name(fb), title = content)
                newpost.p_id = rowc//10+1
                tmppid = rowc//10+1
                newpost.save()
                
                restime = Post_id_restime(newpost.p_id)
                newpost.p_restime.append(restime)
                
                tmpuser.u_post_info.append(newpost)
                tmpuser.save()
            else:
                newmessage = PUM_info(uid = tmpuser.u_id,content = content)
                newmessage.m_id = rowc
                tmpmid = rowc
                newmessage.save()
                
                tmpuser.u_pum_info.append(newmessage)
                tmpuser.save()
                
                addmessage = PUM_pid_mid(pid = tmppid, mid = tmpmid)
                addmessage.save()
                
                tmppost = Post_info.query.filter_by(p_id = tmppid).first()
                tmppost.p_message.append(addmessage)
                tmppost.p_restime[0].p_restime=datetime.now()
                tmppost.save()
                
        for i in userXP.keys():
            tmpuser = User_id_name_pwd.query.filter_by(u_name=i).first()
            tmpuser.u_XP[0].u_XP=userXP[i]
            print(len(tmpuser.u_pum_info))
            tmpuser.save()
    
    init_data()       
    print('create db and admin ok')
    return '创建成功'


@user_blueprint.route('/drop_db/')
def drop_db():
    """
    删除数据库
    """
    print('begin drop db')
    db.drop_all()
    print('drop db ok')
    return '删除成功'


@user_blueprint.route('/home/', methods=['GET'])
@is_login
def home():
    """
    首页
    """
    if request.method == 'GET':
        return render_template('index.html')


@user_blueprint.route('/head/', methods=['GET'])
@is_login
def head():
    """
    页头
    """
    if request.method == 'GET':
        user = session.get('username')
        return render_template('head2.html', user=user)


@user_blueprint.route('/left/', methods=['GET'])
def left():
    """左侧栏"""
    if request.method == 'GET':
        # 获取登录的用户信息
        user = session.get('username')
        # 获取用户的权限
        #print(user)
        grant = User_info.query.join(User_id_name_pwd).filter_by(u_name=user).first().u_grant
        #print(grant)
        if(grant==1):
            permissions = [{'p':'1'}]
        elif(grant==2):
            permissions = [{'p':'1'},{'p':'2'},{'p':'3'}]
        elif(grant==3):
            permissions = [{'p':'1'},{'p':'2'},{'p':'3'},{'p':'4'}]
        elif(grant==4):
            permissions = [{'p':'1'},{'p':'2'},{'p':'3'},{'p':'4'},{'p':'5'}]
        #print(permissions)
        return render_template('left.html', permissions=permissions)


@user_blueprint.route('/register/', methods=['GET', 'POST'])
def register():
    """
    用户注册页面
    """
    if request.method == 'GET':
        return render_template('register.html')

    if request.method == 'POST':
        # 获取用户填写的信息
        username = request.form.get('username')
        pwd1 = request.form.get('pwd1')
        pwd2 = request.form.get('pwd2')

        # 定义个变量来控制过滤用户填写的信息
        flag = True
        # 判断用户是否信息都填写了.(all()函数可以判断用户填写的字段是否有空)
        if not all([username, pwd1, pwd2]):
            msg, flag = '* 请填写完整信息', False
        # 判断用户名是长度是否大于10
        if len(username) > 10:
            msg, flag = '* 用户名太长', False
        # 判断两次填写的密码是否一致
        if pwd1 != pwd2:
            msg, flag = '* 两次密码不一致', False
        # 如果上面的检查有任意一项没有通过就返回注册页面,并提示响应的信息
        if not flag:
            return render_template('register.html', msg=msg)
        # 核对输入的用户是否已经被注册了
        u = User_id_name_pwd.query.filter(User_id_name_pwd.u_name == username).first()
        # 判断用户名是否已经存在
        if u:
            msg = '用户名已经存在'
            return render_template('register.html', msg=msg)
        # 上面的验证全部通过后就开始创建新用户
        user_id_name_pwd = User_id_name_pwd(name=username, pwd=pwd1)
        user_XP = User_XP(uid=user_id_name_pwd.u_id,XP=0)
        user_info = User_info(uid=user_id_name_pwd.u_id,grant=2)
        user_id_name_pwd.u_XP.append(user_XP)
        user_id_name_pwd.u_info.append(user_info)
        # 保存注册的用户
        user_id_name_pwd.save()
        user_XP.save()
        user_info.save()
        # 跳转到登录页面
        return redirect(url_for('user.login'))


@user_blueprint.route('/login/', methods=['GET', 'POST'])
def login():
    """
    登录
    """
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # 判断用户名和密码是否填写
        if not all([username, password]):
            msg = '* 请填写好完整的信息'
            return render_template('login.html', msg=msg)
        # 核对用户名和密码是否一致
        user = User_id_name_pwd.query.filter_by(u_name=username, u_pwd=password).first()
        # 如果用户名和密码一致
        if user:
            # 向session中写入相应的数据
            
            if user.u_info[0].u_state==2:
                msg = '* 您处于封号状态，请联系管理员解除封号'
                return render_template('login.html', msg=msg)
            
            session['user_id'] = user.u_id
            session['username'] = user.u_name
            return render_template('index.html')
        # 如果用户名和密码不一致返回登录页面,并给提示信息
        else:
            msg = '* 用户名或者密码不一致'
            return render_template('login.html', msg=msg)


@user_blueprint.route('/logout/', methods=['GET'])
def logout():
    """
    退出登录
    """
    if request.method == 'GET':
        # 清空session
        session.clear()
        # 跳转到登录页面
        session['username']='anony'
        return redirect(url_for('user.forumblock_list'))

@user_blueprint.route('/fblist/', methods=['GET', 'POST'])
@is_login
def forumblock_list():
    """
    显示版块列表
    """
    if request.method == 'GET':
        # 查询第几页的数据
        page = int(request.args.get('page',1))
        # 每页的条数是多少,默认为5条
        page_num = int(request.args.get('page_num',5))
        # 查询当前第几个的多少条数据
        paginate = FB_info.query.order_by('fb_id').paginate(page,page_num)
        # 获取版块的具体数据
        fbs = paginate.items

        # 返回获取到的版块信息给前端页面
        return render_template('fblist.html', fbs=fbs, paginate=paginate)

@user_blueprint.route('/postlist/', methods=['GET', 'POST'])
@is_login
def post_list():
    """
    显示帖子列表
    """
    if request.method == 'GET':
        fb_id = request.args.get('fb_id')
        posts = Post_info.query.filter(Post_info.fb_id == fb_id).all()
        print(len(posts))
        return render_template('postlist.html', posts=posts )

@user_blueprint.route('/messagelist/', methods=['GET', 'POST'])
@is_login
def message_list():
    """
    显示帖子对应的留言列表
    """
    if request.method == 'GET':
        p_id = request.args.get('p_id')
        session['p_id']=p_id
        mids = PUM_pid_mid.query.filter(PUM_pid_mid.p_id == p_id).all()
        messages = []
        
        for i in mids:
            messages.append(PUM_info.query.get(i.m_id))
            
        print(len(messages))
        return render_template('messagelist.html', messages=messages)

@user_blueprint.route('/userlist/', methods=['GET', 'POST'])
@is_login
def user_list():
    """
    显示用户列表
    """
    if request.method == 'GET':
        users = User_id_name_pwd.query.all()
        return render_template('userlist.html',users=users)

@user_blueprint.route('/addpost/', methods=['GET', 'POST'])
@is_login
def add_post():
    """
    新增帖子
    """
    if request.method == 'GET':
        return render_template('addpost.html')

    if request.method == 'POST':
        user = session.get('username')
        fb_id = request.args.get('fb_id')
        title = request.form.get('title')
        content = request.form.get('content')

        tmpuser = User_id_name_pwd.query.filter_by(u_name=user).first()
        
        if(tmpuser.u_info[0].u_state!=0):
            return '您处于禁言状态，无权发表帖子'
        
        p = Post_info(uid=tmpuser.u_id,fbid=fb_id,title=title)
        p.p_id = db.session.query(func.max(Post_info.p_id)).scalar()+1
        
        print(p.p_id)
        
        puminfo=PUM_info(uid=tmpuser.u_id,content=content)
        puminfo.m_id = db.session.query(func.max(PUM_info.m_id)).scalar()+1
        puminfo.save()
        tmpuser.u_pum_info.append(puminfo)
        print(puminfo.m_id)
        
        pumpmid = PUM_pid_mid(pid=p.p_id,mid=puminfo.m_id)
        pumpmid.save()
        print(PUM_pid_mid.query.filter_by(m_id=puminfo.m_id).first().p_id)
        print(pumpmid.m_id)
        p.p_message.append(pumpmid)
        
        pir = Post_id_restime(pid=p.p_id)
        pir.save()
        p.p_restime.append(pir)
        
        p.save()
        
        tmpuser.u_post_info.append(p)
        tmpuser.u_XP[0].u_XP+=50
        tmpuser.save()
        
        fb = FB_info.query.filter_by(fb_id=fb_id).first()
        fb.fb_updatetime = datetime.now()
        fb.save()

        return redirect(url_for('user.post_list',fb_id=fb_id))

@user_blueprint.route('/changefbmaster/', methods=['GET', 'POST'])
@is_login
def change_fb_master():
    """
    修改版主
    """
    
    if request.method == 'GET':
        return render_template('changefbmaster.html',msg=' ')

    if request.method == 'POST':
        
        user = session['username']
        if(user!='admin'):
            return render_template('changefbmasterfa.html')
        
        fbid = request.args.get('fb_id')
        mID = request.form.get('mID')
        user = User_id_name_pwd.query.filter(User_id_name_pwd.u_name == mID).first()
        
        if not user:
            msg = '*该用户不存在'
            return render_template('changefbmaster.html', msg=msg)
       
        fb = FB_info.query.filter(FB_info.fb_id == fbid).first()
        fb.fb_masterid=user.u_id
        fb.fb_mastername=user.u_name
        
        fb.save()

        return redirect(url_for('user.forumblock_list'))

@user_blueprint.route('/delpost/', methods=['GET', 'POST'])
@is_login
def del_post():
    """
    删除帖子
    """
    if request.method == 'GET':
        fb_id = request.args.get('fb_id')
        p_id = request.args.get('p_id')
        post = Post_info.query.get(p_id)
        
        print(p_id)
        if not post:
            print('del post:post not found')
        
        if not fb_id:
            fb_id = post.fb_id
        
        print(fb_id)
        fb = FB_info.query.filter_by(fb_id=fb_id).first()
        
        user=session['username']
        
        if(user!='admin' and user!=fb.fb_mastername):
            return render_template('delpostfa.html')
        
        mids = PUM_pid_mid.query.filter_by(p_id=p_id).all()
        for i in mids:
            messages = PUM_info.query.get(i.m_id)
            db.session.delete(messages)
        
        db.session.delete(post)
        db.session.commit()
        
        #更新版块
        
        fb.fb_updatetime = datetime.now()
        fb.save()        
        
        return render_template('delpostsu.html')

@user_blueprint.route('/addmessage/', methods=['GET', 'POST'])
@is_login    
def add_message():
    """
    新增留言
    """
    if request.method == 'GET':
        return render_template('addmessage.html')

    if request.method == 'POST':
        user=session['username']
        
        if(user=='anony'):
            return render_template('addmessagefa.html')
        
        tmpuser = User_id_name_pwd.query.filter_by(u_name=user).first()
        if(tmpuser.u_info[0].u_state!=0):
            return render_template('addmessagefa.html')
        
        pid = session['p_id']
        content = request.form.get('content')
        
        p = PUM_info(uid=tmpuser.u_id,content=content)
        p.save()
        
        tmpuser.u_pum_info.append(p)
        tmpuser.save()
        
        pumpmid = PUM_pid_mid(pid=pid, mid=p.m_id)
        pumpmid.save()
        
        tmppost = Post_info.query.filter_by(p_id=pid).first()
        tmppost.p_message.append(pumpmid)
        tmppost.p_restime[0].p_restime = datetime.now()
        tmppost.save()
        
        fb_id = request.args.get('fb_id')
        if not fb_id:
            fb_id = tmppost.fb_id
        fb = FB_info.query.filter_by(fb_id=fb_id).first()
        
        fb.fb_updatetime = datetime.now()
        fb.save()
        
        return redirect(url_for('user.message_list',p_id=pid))

@user_blueprint.route('/editmessage/', methods=['GET', 'POST'])
@is_login
def edit_message():
    """
    修改留言
    """
    
    return render_template('editmessage.html')

@user_blueprint.route('/delmessage/', methods=['GET', 'POST'])
@is_login
def del_message():
    """
    删除留言
    """
    if request.method == 'GET':
        fb_id = request.args.get('fb_id')
        
        user=session['username']
        
        m_id = request.args.get('m_id')
        message = PUM_info.query.get(m_id)
        print(m_id)
        
        if not message:
            print('message not found')
        
        if not fb_id:
            print(PUM_pid_mid.query.filter_by(m_id=m_id).first())
            p_id=PUM_pid_mid.query.filter_by(m_id=m_id).first().p_id
            post=Post_info.query.filter_by(p_id=p_id).first()
            fb_id=post.fb_id
        
        fb = FB_info.query.filter_by(fb_id=fb_id).first()
        
        if(user!=fb.fb_mastername and user!='admin' and user!=message.u_id):
            return render_template('delmessagefa.html')
        
        db.session.delete(message)
        db.session.commit()
        
        fb.fb_updatetime = datetime.now()
        fb.save()
        
        return render_template('delmessagesu.html')

@user_blueprint.route('/changestate1/', methods=['GET', 'POST'])
@is_login
def change_state_1():
    """
    修改用户权限(封号，禁言)
    """
    if request.method == 'GET':
        username = session.get('username')
        user = User_id_name_pwd.query.filter_by(u_name=username).first()
        if(user.u_id!=1):
            return render_template('changestatefa.html')
        else:
            uid =  request.args.get('u_id')
        
            user = User_info.query.filter_by(u_id=uid).first()
            user.u_state = 1
            user.save()
            return redirect(url_for('user.user_list'))

@user_blueprint.route('/changestate2/', methods=['GET', 'POST'])
@is_login
def change_state_2():
    """
    修改用户权限(封号，禁言)
    """
    if request.method == 'GET':
        username = session.get('username')
        user = User_id_name_pwd.query.filter_by(u_name=username).first()
        if(user.u_id!=1):
            return render_template('changestatefa.html')
        else:
            uid =  request.args.get('u_id')
            user = User_info.query.filter_by(u_id=uid).first()
            user.u_state = 2
            user.save()
            #db.session.commit()
        
            return redirect(url_for('user.user_list'))

    if request.method == 'POST':
        uid =  request.args.get('u_id')
        flag = request.args.get('flag')
        
        print(flag)
        
        if flag=='1' :
            user = User_info.query.filter_by(u_id=uid).first()
            user.u_state = 1
            db.session.commit()
        
        if flag=='2' :
            user = User_info.query.filter_by(u_id=uid).first()
            user.u_state = 2
            db.session.commit()
        
        return redirect(url_for('user.user_list'))
    
@user_blueprint.route('/changestate3/', methods=['GET', 'POST'])
@is_login
def change_state_3():
    """
    修改用户权限(封号，禁言)
    """
    if request.method == 'GET':
        username = session.get('username')
        user = User_id_name_pwd.query.filter_by(u_name=username).first()
        if(user.u_id!=1):
            return render_template('changestatefa.html')
        else:
            uid =  request.args.get('u_id')
        
            user = User_info.query.filter_by(u_id=uid).first()
            user.u_state = 0
            user.save()
            return redirect(url_for('user.user_list'))

@user_blueprint.route('/changestate4/', methods=['GET', 'POST'])
@is_login
def change_state_4():
    """
    修改用户权限(封号，禁言)
    """
    if request.method == 'GET':
        username = session.get('username')
        user = User_id_name_pwd.query.filter_by(u_name=username).first()
        if(user.u_id!=1):
            return render_template('changestatefa.html')
        else:
            uid =  request.args.get('u_id')
        
            user = User_info.query.filter_by(u_id=uid).first()
            user.u_state = 0
            user.save()
            return redirect(url_for('user.user_list'))
    
@user_blueprint.route('/changepwd/', methods=['GET', 'POST'])
@is_login
def change_password():
    """修改用户密码"""
    if request.method == 'GET':
        username = session.get('username')
        user = User_id_name_pwd.query.filter_by(u_name=username).first()
        return render_template('changepwd.html', user=user)

    if request.method == 'POST':
        username = session.get('username')
        newname = request.form.get('newname')
        pwd1 = request.form.get('pwd1')
        pwd2 = request.form.get('pwd2')
        pwd3 = request.form.get('pwd3')

        pwd = User_id_name_pwd.query.filter(User_id_name_pwd.u_pwd == pwd1, User_id_name_pwd.u_name == username).first()
        
        if newname:
            user = User_id_name_pwd.query.filter_by(u_name=username).first()
            user.u_name = newname
            db.session.commit()
            return redirect(url_for('user.change_name_sucess'))
        
        if not pwd:
            msg = '请输入正确的旧密码'
            username = session.get('username')
            user = User_id_name_pwd.query.filter_by(u_name=username).first()
            return render_template('changepwd.html', msg=msg, user=user)
        else:
            if not all([pwd2, pwd3]):
                msg = '密码不能为空'
                username = session.get('username')
                user = User_id_name_pwd.query.filter_by(u_name=username).first()
                return render_template('changepwd.html', msg=msg, user=user)
            if pwd2 != pwd3:
                msg = '两次密码不一致,请重新输入'
                username = session.get('username')
                user = User_id_name_pwd.query.filter_by(u_name=username).first()
                return render_template('changepwd.html', msg=msg, user=user)
            pwd.u_pwd = pwd2
            db.session.commit()
            return redirect(url_for('user.change_pass_sucess'))


@user_blueprint.route('/changepwdsu/', methods=['GET'])
@is_login
def change_pass_sucess():
    """修改密码成功后"""
    if request.method == 'GET':
        return render_template('changepwdsu.html')

@user_blueprint.route('/changenamesu/', methods=['GET'])
@is_login
def change_name_sucess():
    """修改昵称成功后"""
    if request.method == 'GET':
        return render_template('changepwdsu.html')

@user_blueprint.route('/personallist/', methods=['GET', 'POST'])
@is_login
def personal_list():
    """
    显示单个用户对应的留言列表
    """
    if request.method == 'GET':
        u_id = request.args.get('u_id')
        messages = PUM_info.query.filter(PUM_info.u_id == u_id).all()
        #print(messages)
        return render_template('personallist.html', u_id=u_id, messages=messages)

@user_blueprint.route('/postsearchall/', methods=['GET', 'POST'])
@is_login
def postsearchall():
    if request.method == 'GET':
        return render_template('searchpostbytitle.html')
    
    if request.method == 'POST':
        keywords = request.form.get('keywords')
        posts = Post_info.query.filter(Post_info.p_title.like('%'+keywords+'%')).all()
        return render_template('postlist.html', posts=posts)

"""
@user_blueprint.route('/addgrade/', methods=['GET', 'POST'])
@is_login
def add_grade():
    if request.method == 'GET':
        return render_template('addgrade.html')

    if request.method == 'POST':
        g_name = request.form.get('g_name')
        g = Grade.query.filter(Grade.g_name == g_name).first()
        # 判断要添加的信息数据库中是否存在(因为班级名称不能重复)
        if g:
            msg = '*班级名称不能重复,请核对好在来添加'
            return render_template('addgrade.html', msg=msg)
        # 创建班级
        grade = Grade(g_name)
        # 保存班级信息
        grade.save()

        return redirect(url_for('user.grade_list'))
"""