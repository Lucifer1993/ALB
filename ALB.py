#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : Lucifer
# @Time    : 2019-01-04 18:18
# @File    : ALB.py
# @Software: PyCharm
# -*- coding: utf-8 -*-
from gevent import monkey
from gevent.pool import Pool
monkey.patch_all()
import re
import click
from urllib.parse import unquote

rules = {
    'SQLinject': {
        'UNION注入': r'union.*select.*from',
        'MSSQL报错注入': r'(and|or).*(in.*select|=convert|=concat)',
        'MySQL报错注入': r'(and|or).*(extractvalue|updatexml|floor)',
        'Oracle报错注入': r'(and|or).*(UPPER.*XMLType|utl_inaddr|ctxsys|dbms_utility)',
        'MySQL盲注': r'(and|or).*(rlike|make_set|elt|sleep)',
        'Oracle盲注': r'select.*case[\s\S]when.*=.*then.*dual',
        'Oracle时间盲注': r'(and|or|begin|select).*(dbms_pipe|select.*from.*all_users|dbms_lock)',
        'MSSQL盲注': r'select.*case[\s\S]when.*=.*then',
        'MSSQL时间盲注': r'(and|or|select).*(from.*sysusers|waitfor[\s\S]delay)',
        },
    'ArbitraryFileOperation':{
        '任意文件读取/包含(linux)': r'[.]+/',
        '任意文件读取/包含(windows)': r'[.]+\\',
    },
    'dirtraversal':{
        'windows路径穿越': r'(win.ini|system.ini|boot.ini|cmd.exe|global.asa)',
        'linux路径穿越': r'(/etc/passwd|/etc/shadow|/etc/hosts|.htaccess|.bash_history)',
    },
    'ArbitraryCodeExcute':{
        '任意代码执行': r'(=.*phpinfo|=.*php://|=.*\$_post\[|=.*\$_get\[|=.*\$_server\[|=.*exec\(|=.*system\(|=.*call_user_func|=.*passthru\(|=.*eval\()',
    },
    'struts2vuln':{
        'struts005~009': r'xwork.MethodAccessor.denyMethodExecution',
        'struts013': r'_memberAccess.*ServletActionContext',
        'struts016': r'redirect:.*context.get',
        'struts019': r'xwork2.dispatcher.HttpServletRequest',
        'struts032~057': r'@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS',
    },
    'XSS':{
        'general': r'(<script|<img|<object|<style|<div|<table|<iframe|<meta|<body|<svg|<embed|<a|<input|<marquee|<link|<xml|<image|<html).*(alert|prompt|confirm)',
        'flashxss': r'javascript:alert',
    },
}
f = open('./result.txt', 'w+')

def analysisattack(log):
    for key, value in rules.items():
        for key2, value2 in value.items():
            try:
                match = re.search(value2, log, re.IGNORECASE)
                if match:
                    f.write('[*]日志: {0}\n'.format(log))
                    res = '[!]漏洞类型: {0}\t漏洞细节: {1}\t匹配规则: {2}'.format(key, key2, value2)
                    print(res)
                    f.write('{0}\n\n'.format(res))
                    return
            except:
                print('[-] 日志分析失败: {0}'.format(log))

@click.command()
@click.option('-f', type=str, help='日志文件路径')
@click.option('-t', default=100, type=int, help='设置并发线程数')

def analysislog(f, t):
    pool = Pool(t)
    logs = list()
    with open(f, 'r') as fp:
        for line in fp:
            logs.append(unquote(line.strip()))
    totalcount = len(logs)
    print('[*] 日志数: {0}'.format(totalcount))
    pool.map(analysisattack, logs)

if __name__ == '__main__':
    analysislog()
