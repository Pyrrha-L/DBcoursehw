# -*- coding: utf-8 -*-
"""
Created on Mon Dec 16 11:01:15 2019

@author: 李梓童
"""

v<!-- MainForm 
    <ul id="PageNum">

        <li><a href="/user/postlist/?fb_id={{ fb_id }}&?page=1">首页</a></li>
        {% if paginate.has_prev %}
            <li><a href="/user/postlist/?fb_id={{ fb_id }}&?page={{ paginate.prev_num }}">上一页</a></li>
        {% endif %}

        {% for p  in paginate.iter_pages() %}
            <li>
                {% if p %}
                    {% if p != paginate.page %}
                    <a href="/user/postlist/?fb_id={{ fb_id }}&?page={{ p }}">{{ p }}</a>
                    {% else %}
                    <span> {{ p }} </span>
                    {% endif %}
                {% else %}
                    <span>...</span>
                {% endif %}
            </li>
        {% endfor  %}

        {% if paginate.has_next %}
            <li><a href="/user/postlist/?fb_id={{ fb_id }}&?page={{ paginate.next_num }}">下一页</a></li>
        {% endif %}
            <li><a href="/user/postlist/?fb_id={{ fb_id }}&?page={{ paginate.pages }}">尾页</a></li>
        <span>| 共{{paginate.pages}}页 | 当前第{{paginate.page}}页</span>
    </ul>
-->