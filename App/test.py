# -*- coding: utf-8 -*-
"""
Created on Thu Dec 19 20:12:56 2019

@author: 李梓童
"""

from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User_id_name_pwd(db.Model): # 类名首字母大写
    u_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    u_name = db.Column(db.String(20), unique=True)
    u_pwd = db.Column(db.String(30))
    
    u_XP = db.relationship('User_XP',backref= 'user_id_name_pwd')
    u_info = db.relationship('User_info',backref= 'user_id_name_pwd')
    u_post_info = db.relationship('Post_info',backref= 'user_id_name_pwd')
    u_pum_info = db.relationship('PUM_info',backref= 'user_id_name_pwd')
    
    __tablename__ = 'user_id_name_pwd'  # 表名首字母小写

    def __init__(self, name, pwd):
        self.u_name = name
        self.u_pwd = pwd

    def save(self):
        db.session.add(self)
        db.session.commit()

class User_XP(db.Model): # 类名首字母大写 
    u_id = db.Column(db.Integer, db.ForeignKey('user_id_name_pwd.u_id'),primary_key=True) #autoincrement=True, primary_key=True
    u_XP = db.Column(db.Integer, nullable=True)

    __tablename__ = 'user_XP'  # 表名首字母小写

    def __init__(self, uid, XP):
        self.u_id=uid
        self.u_XP=XP
        
    def save(self):
        db.session.add(self)
        db.session.commit()
        
class User_info(db.Model): # 类名首字母大写
    u_id = db.Column(db.Integer, db.ForeignKey('user_id_name_pwd.u_id'),primary_key=True) #autoincrement=True, primary_key=True
    u_grant = db.Column(db.Integer, nullable=True)
    u_reg_time = db.Column(db.DateTime, default=datetime.now)
    u_grade = db.Column(db.Integer, nullable=True, default=1)
    u_state = db.Column(db.Integer, nullable=True, default=0)

    __tablename__ = 'user_info'  # 表名首字母小写

    def __init__(self, uid, grant):
        self.u_id=uid
        self.u_grant=grant

    def save(self):
        db.session.add(self)
        db.session.commit()

class Post_id_restime(db.Model): #respond time
    """
    帖子id-留言时间表
    """
    p_id = db.Column(db.Integer, db.ForeignKey('post_info.p_id'),primary_key=True) #autoincrement=True, primary_key=True
    p_restime = db.Column(db.DateTime, default=datetime.now)
    
    __tablename__ = 'post_id_restime'
    
    def __init__(self,pid):  #补齐参数
        self.p_id=pid
    
    def updatetime(self):
        self.p_restime = datetime.now()
        
    def save(delf):
        db.session.add(self)
        db.session.commit()
        
class Post_info(db.Model):
    """
    帖子id-用户id-版块id-发帖时间-帖子标题
    """
    p_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    u_id = db.Column(db.Integer, db.ForeignKey('user_id_name_pwd.u_id'))
    fb_id = db.Column(db.Integer, db.ForeignKey('fb_info.fb_id'))
    p_ptime = db.Column(db.DateTime, default=datetime.now)
    p_title = db.Column(db.String(350))
    
    p_restime = db.relationship('Post_id_restime',backref= 'post_info')
    p_message = db.relationship('PUM_pid_mid',backref= 'post_info')
    
    __tablename__ = 'post_info'
    
    def __init__(self,uid,fbid,title):  #补齐参数
        self.u_id=uid
        self.fb_id=fbid
        self.p_title=title
        
    def save(self):
        db.session.add(self)
        db.session.commit()
        
class PUM_pid_mid(db.Model):
    """
    帖子id-留言id
    """
    
    p_id = db.Column(db.Integer, db.ForeignKey('post_info.p_id',ondelete='CASCADE')) #autoincrement=True, primary_key=True
    m_id = db.Column(db.Integer, db.ForeignKey('pum_info.m_id',ondelete='CASCADE'), primary_key=True)
    
    __tablename__ = 'pum_pid_mid'
    
    def __init__(self, pid, mid):  #补齐参数
        self.p_id = pid
        self.m_id = mid
        
    def save(self):
        db.session.add(self)
        db.session.commit()
        
class PUM_info(db.Model):
    """
    留言id-用户id-留言内容-留言时间
    """
    
    m_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    u_id = db.Column(db.Integer, db.ForeignKey('user_id_name_pwd.u_id'))
    m_content = db.Column(db.String(350))
    m_time = db.Column(db.DateTime, default=datetime.now)
    
    pum_pid = db.relationship('PUM_pid_mid',backref= 'pum_info')
    
    __tablename__ = 'pum_info'
    
    def __init__(self,uid,content):  #补齐参数
        self.u_id = uid
        self.m_content = content
        
    def save(self):
        db.session.add(self)
        db.session.commit()

class FB_info(db.Model):
    """
    版块id-版块主题-版主id-最后更新时间
    """
    fb_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    fb_theme = db.Column(db.String(30))
    fb_masterid = db.Column(db.Integer,nullable=True,default=0)
    fb_mastername = db.Column(db.String(20),default='None')
    fb_updatetime = db.Column(db.DateTime, default=datetime.now)
    
    fb_post_info = db.relationship('Post_info',backref= 'fb_info')
    
    __tablename__ = 'fb_info'
    
    def __init__(self,theme):  #补齐参数
        self.fb_theme = theme
        
    def updatetime(self):
        self.fb_updatetime = datetime.now
        
    def save(self):
        db.session.add(self)
        db.session.commit()
'''
u1=User_id_name_pwd('A1','123')
u1.u_id=2
p1=Post_info(uid=2,fbid=1,title='aaaaa')
u1.u_post_info.append(p1)
print(u1)
print(p1)
print(u1.u_post_info[0].p_title)
u1.u_post_info[0].p_title='bbbb'
print(u1.u_post_info[0].p_title)
p1.u_id=3
print(u1.u_post_info[0].u_id)
print(p1.user_id_name_pwd.u_id)
'''

print(datetime.now().strftime("%Y/%m/%d"))