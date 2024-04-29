use std::{error::Error, fs::File, io::Write, time::Instant};

use http_req::request;
use regex::Regex;

use crate::{model::{config::Config, UnauthorizedInterface, Interfaces}, util::rule_check::{TOTAL_LINE, NOT_NULL_LINE}};

pub mod java_project;
pub mod php_project;
pub mod go_project;

pub struct JAVAProject;
pub struct PHPProject;
pub struct GOProject;

/**
 * 启动结构体
 * @Field project 实现功能的结构体代码
 * @Field config 配置信息
 */
pub struct Application<T>
    where T: Scanner{
    pub project: T,
    pub config: Config
}

/**
 * 实现启动方法，通过调用实现了Scanner trait的结构体来完成抽象
 */
impl<T: Scanner> Application<T> {

    
    pub fn start(project: T, mut config: Config, report_file: &mut File) -> Result<(), Box<dyn Error>> {
        let start_time = Instant::now();
        project.init(&mut config, report_file)?;
        // 开始扫描任务，获取接口列表
        let interface_list = project.start(&mut config, report_file)?;
        // 扫描行数统计
        {
            match report_file.write(format!(
                "\n  \n# 本次扫描共计: {}行,不为空的行数为: {}行", TOTAL_LINE.lock().unwrap(), NOT_NULL_LINE.lock().unwrap())
            .as_bytes()) {
                Ok(_) => println!("[+]行数统计成功"),
                Err(_) => println!("[-]统计行数失败了!"),
            }
        }
        // 是否需要对接口进行验证
        if config.unauthorized.valid {
            // 初始要访问根路由
            let mut unauthorized_interfaces: Vec<UnauthorizedInterface> = Vec::new();
            for mut interface in interface_list {
                interface.insert_str(0, &config.unauthorized.prefix);
                match Self::send_request(&interface) {
                    Ok((code, body)) => {
                        // 如果响应头满足了
                        if config.unauthorized.rule.status_code.contains(&code) {
                            unauthorized_interfaces.push(UnauthorizedInterface{
                                code,
                                body,
                                url: interface,
                            });
                            continue;
                        }
                        // 响应体满足
                        config.unauthorized.rule.response_body.clone().into_iter().for_each(|rule|{
                            let body_clone = body.clone();
                            let mut flag = false;
                            if "Contains".eq(&rule.match_rule) && rule.value.contains(&body) {
                                flag = true;
                            } else if "Regex".eq(&rule.match_rule) {
                                match Regex::new(&rule.value) {
                                    Ok(reg) => {
                                        reg.find(&body).is_some().then(||{
                                            flag = true
                                        });
                                        print!("")
                                    },
                                    Err(_) => println!("正则表达式: {}非法", rule.match_rule),
                                }
                                flag = true
                            } else if "NotContains".eq(&rule.match_rule) {
                                flag = true
                            } else {
                                println!("规则: {}不是合法的规则类型", rule.match_rule);
                            }
                            if flag {
                                unauthorized_interfaces.push(UnauthorizedInterface{
                                    code,
                                    body: body_clone,
                                    url: interface.clone()
                                });
                            }
                        });
                    },
                    Err(err) => {
                        println!("请求url{}: 出现错误: {:?}", interface, err);
                    },
                };
            }
            // 写入报告未授权接口
            let mut unauthorized_interface_info: String = String::from("### 未授权接口列表:   \n```\n");
            for interface in &unauthorized_interfaces {
                unauthorized_interface_info.push_str(format!(" - [Code]:{} [URL]{} \n[Body]{}", interface.code, interface.url, interface.body).as_str())
            }
            unauthorized_interface_info.push_str("\n```\n");
            report_file.write(unauthorized_interface_info.as_bytes())?;
            println!("未授权接口扫描完毕")
        }
        let end_time = Instant::now();
        let duration = end_time - start_time;
        println!("本次项目扫描执行时间: {}", Self::format_duration(duration));
        
        Ok(())
    }

    // 格式化输出时间
    fn format_duration(duration: std::time::Duration) -> String {
        let seconds = duration.as_secs();
        let minutes = seconds / 60;
        let hours = minutes / 60;
        let seconds_remaining = seconds % 60;
        let minutes_remaining = minutes % 60;
    
        format!("{:02}:{:02}:{:02}", hours, minutes_remaining, seconds_remaining)
    }
    // 发送请求
    fn send_request(url: &str) -> Result<(u16, String), Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();
        let response = request::get(url, &mut buffer)?;
        // 获取响应状态码
        let status_code = u16::from(response.status_code());
        // 将请求体转换为字符串
        let response_body = String::from_utf8_lossy(&buffer).to_string();
    
        Ok((status_code, response_body))
    }
}

/**
 * 功能代码接口
 * @fn init 初始化函数，加载配置
 * @fn start 正式启动扫描任务
 */
pub trait Scanner {
    // 默认所有的项目扫描都需要加载初始的配置文件
    fn init(&self, _config: &mut Config, report_file: &mut File) -> Result<(), Box<dyn Error>>{
        let config_out: String = format!("# 项目《{}》扫描结果报告:  \n\n### 本次扫描加载的初始配置为:   \n```\n{:#?}\n```  \n\n", _config.project_name, _config);
        report_file.write(config_out.as_bytes())?;
        _config.load_rule()?;
        let mut rule_out: String = String::from("### 加载规则文件列表如下:  \n\n```\n");
        for item in &_config.rule {
            rule_out.push_str(format!("- {:?}\n", item).as_str())
        }
        rule_out.push_str("\n```  \n\n");
        report_file.write(rule_out.as_bytes())?;
        println!("[+]规则加载完毕，共计使用规则共：{:?}条", _config.rule.len());
        Ok(())
    }

    fn start(&self, _config: &mut Config, _report_file: &mut File) -> Result<Interfaces, Box<dyn Error>>{
        Ok(vec![])
    }
}