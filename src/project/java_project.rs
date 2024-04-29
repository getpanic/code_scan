use std::{fs::{File, self}, error::Error, io::{Write, BufReader, BufRead}, path::PathBuf};

use regex::Regex;
use xmltree::Element;

use crate::{model::{config::Config, Interfaces}, util::{PathUtil, rule_check::RuleCheck, FileUtil}, enums::{Framwork, ORM}};

use super::{JAVAProject, Scanner};

impl Scanner for JAVAProject {
    fn start(&self, config: &mut Config, report_file: &mut File) -> Result<Interfaces, Box<dyn Error>>{
        // 依赖信息收集
        match Self::collection_dependcy(config.depency_file.clone(), report_file) {
            Ok(_) => println!("[+]组件信息收集完毕"),
            Err(_err) => println!("[-]组件信息收集失败=>[{}]", _err),
        }
        // 要扫描的代码文件后缀路径收集
        let file_path_list: Vec<String> = FileUtil::collection_file(&config.work_dir, &config.scan_ext, &config.exclude_path)?;
        let mut file_list_info: String = String::from("### 根据后缀找到文件列表:   \n```\n");
        // 获取去掉前缀，只保留项目路径
        for file_path in &PathUtil::clear_prefix(file_path_list.clone(), &config.work_dir) {
            file_list_info.push_str(format!(" - {}\n", file_path).as_str())
        }
        file_list_info.push_str("\n```\n\n");
        report_file.write(file_list_info.as_bytes())?;
        println!("[+]要扫描的文件收集完毕");
        let mut interface_list: Interfaces = Vec::new();
        // 收集接口地址
        if config.collection_interface {
            interface_list = Self::collection_interface(&file_path_list, &config, report_file)?;
            report_file.write(format!("### 扫描出的接口列表:   \n```\n{:#?}\n```\n", interface_list).as_bytes())?;
            println!("[+]接口地址收集完毕");
        }
        // 根据扫描规则跑出来的漏洞
        RuleCheck::start(&config.rule, file_path_list, report_file, config.use_ui)?;
        println!("[+]基于规则漏洞扫描完毕");

        // 检查ORM中容易出现的SQL注入
        match config.orm {
            ORM::Mybatis => {
                match Self::analyze_mybatis_sql_injection(&config.work_dir, &config.exclude_path, report_file) {
                    Ok(_) => println!("[+]mybatis框架 SQL注入扫描完毕"),
                    Err(err) => println!("[-]mybatis框架 SQL注入扫描失败, err: [{:#?}]", err),
                } 
            },
            ORM::Hibernate => println!("Hibernate todo"),
            ORM::None => println!("未使用ORM框架,skip")
        }

        Ok(interface_list)
    }

}


impl JAVAProject {
    /**
     * @description 收集接口信息
     * @param file_list 要扫描的文件绝对路径地址
     * @param lang 审计语言类型
     * @param framework 开发框架
     * @param work_dir 项目根目录
     * @return Interfaces 接口列表
     */
    fn collection_interface(path_list: &Vec<String>, config: &Config, report_file: &mut File) -> Result<Interfaces, Box<dyn Error>> {
        let mut interface_list: Interfaces = vec![];
        interface_list.append(&mut Self::collection_java_interface(&config.work_dir, report_file)?);
        let mut _framework_interface: Interfaces = vec![];
        _framework_interface = match config.framework {
            // 识别@RequestMapping
            Framwork::Spring => Self::collection_spring(&path_list)?,
            // 识别Struts配置文件
            Framwork::Struts => Self::collection_struts(&config.work_dir)?,
            // 识别Struts2配置文件
            Framwork::Struts2 => Self::collection_struts2(&config.work_dir)?,
            Framwork::None => {
                println!("未使用开发框架，跳过特定检查");
                vec![]
            },
            _ => panic!("配置中填写的框架非java框架,请检查配置文件!")
        };
        interface_list.append(&mut _framework_interface);
        interface_list.append(&mut Self::collection_jsp(path_list.clone(), &config.work_dir)?);
        Ok(interface_list)
    }

    /**
     * @descript 分析Mybatis中的SQL注入
     * @param root_dir 项目根目录
     * @param exclude_path 排除的目录
     * @return Result<(), err> 是否出现错误
     */
    pub fn analyze_mybatis_sql_injection(root_dir: &str, exclude_path: &Vec<String>, report_file: &mut File) -> Result<(), Box<dyn Error>>{        
        let xml_files = FileUtil::collection_file(&root_dir, &vec![String::from("xml")], exclude_path)?;
        report_file.write("### mybatis找到SQL注入风险点:\n```\n".as_bytes())?;
        for xml_file in xml_files {
            // 读取xml文件
            let xml_content = FileUtil::read_file_by_path(&xml_file);
            // 读取失败跳过该文件，不进行检查
            if xml_content.is_empty() {
                continue;
            }
            // 该文件是否存在漏洞
            let mut have_vul = false;
            // 定义用于匹配 Mybatis XML 文件的正则表达式模式
            let pattern = r#"<\s*mapper.*?>"#;
            // 创建正则表达式对象
            let re = Regex::new(pattern)?;
            // 判断文件内容是否匹配 Mybatis XML 文件的模式
            if re.is_match(&xml_content) {
                // 找到${}注入形式的字符串
                let pattern: &str = r#"\$\{(.*?)\}"#;
                let re = Regex::new(pattern)?;
                // 记录命中行数和次数
                let mut line_number = 0;
                // 按行读取
                let file = File::open(&xml_file)?;
                let reader = BufReader::new(file);
                for line_result in reader.lines() {
                    let line = line_result?;
                    line_number += 1;

                    if re.is_match(&line) {
                        // 第一个存在漏洞的需要写入文件名
                        if have_vul == false {
                            report_file.write(format!(" [-]文件[{}]存在漏洞：\n", xml_file).as_bytes())?;
                            have_vul = true;
                        }
                        report_file.write(format!("    [{}]行命中规则: {}\n", line_number, line).as_bytes())?;
                    }
                }
            }
        }
        report_file.write("\n```\n".as_bytes())?;
        Ok(())
    }
    
    /**
     * @descript 收集pom.xml中的依赖
     * @param depency_file 依赖文件路径
     * @param report_file 报告文件
     * @return Result<(), err> 是否出现错误
     */
    pub fn collection_dependcy(depency_file: String, report_file: &mut File) -> Result<(), Box<dyn Error>> {
        // 未找到pom.xml
        if !PathBuf::from(&depency_file).exists() {
            println!("[-]pom.xml依赖文件不存在,跳过检查");
            return Ok(())
        }
        let mut dependcy_list = Vec::new();
        // 读取文件
        let xml = fs::read_to_string(depency_file)?;
        let pom = Element::parse(xml.as_bytes());
        if pom.is_err() {
            println!("[-]未找到dependcie标签");
            return Ok(())
        }
        let mut pom = pom?;
        // 初始化<dependcies> 标签
        let mut _properties = Some(None);
        // 读取properties
        _properties = Some(pom.take_child("properties"));

        // 读取decency信息
        if let Some(mut depencies) = pom.take_child("dependencies") {
            while let Some(depency) = depencies.take_child("dependency") {
                let mut dependcy_info = String::from("找到组件信息: [");
                // 提取<groupId>
                if let Some(group_id) = depency.get_child("groupId"){
                    dependcy_info.push_str(&format!("{}.", group_id.get_text().unwrap_or(std::borrow::Cow::Borrowed("unknow"))));
                }
                // 提取<artifactId>
                if let Some(artifact_id) = depency.get_child("artifactId"){
                    dependcy_info.push_str(&format!("{}", artifact_id.get_text().unwrap_or(std::borrow::Cow::Borrowed("unknow"))));
                }
                // 提取<version>，处理可能存在${common.version}，到<properties>中查找
                if let Some(version) = depency.get_child("version"){
                    if _properties.is_some() {
                        let properties = _properties.clone().unwrap().unwrap();
                        let version_place = version.get_text().unwrap().replace("${", "").replace("}", "");
                        if let Some(real_version) = properties.get_child(version_place) {
                            dependcy_info.push_str(&format!("-version:{}]", real_version.get_text().unwrap_or(std::borrow::Cow::Borrowed("unknow"))));
                        } else {
                            dependcy_info.push_str(&format!("-version:{}", version.get_text().unwrap_or(std::borrow::Cow::Borrowed("unknow"))))
                        }
                    }
                }
                dependcy_info.push(']');

                dependcy_list.push(dependcy_info);
            }
        }
        // 把内容记录进入文件
        let mut dependcies_ifno: String = String::from("### 组件依赖如下:\n```\n");
        for dependcy in &dependcy_list {
            dependcies_ifno.push_str(format!("- {}\n", dependcy).as_str())
        }
        dependcies_ifno.push_str("\n```\n");
        report_file.write(dependcies_ifno.as_bytes())?;
        Ok(())
    }

    /**
     * @descript 收集Spring framework中的路由地址
     * @param path_list 筛选后缀后到文件路径列表
     * @result Intefaces 收集到的接口信息列表
     */
    fn collection_spring(path_list: &Vec<String>) -> Result<Interfaces, Box<dyn Error>> {
        let mut interfaces: Interfaces = vec![];
        for path in path_list {
            let source_code = FileUtil::read_file_by_path(&path);
            // 初步筛选
            if source_code.contains("@RequestMapping") {
                // 第一个作为前缀
                let mut prefix = String::new();
                // 匹配类上含有路由注解的正则
                let class_level_url_pattern = Regex::new(r#"@RequestMapping\s*\("([^"]*)"\)"#).unwrap();
                // 匹配命中类上含有@RequestMapping的类
                if let Some(captures) = class_level_url_pattern.captures(&source_code) {
                    prefix = captures[1].to_owned();
                    if !prefix.starts_with("/"){
                        prefix.insert(0, '/')
                    }
                }
                // 匹配代码中的接口路由参数
                let pattern = r#"@{1}(PostMapping|GetMapping|PutMapping|DeleteMapping|RequestMapping)\(.*?\)"#;
                let re = Regex::new(pattern).unwrap();
                // 开始正则匹配注解
                for capture in re.captures_iter(&source_code) {
                    let annotation = &capture[0];
                    // URL提取正则
                    let pattern = r#"("[^"]+")|(\w+\s*=\s*"[^"]+")"#;
                    let url_regex = Regex::new(pattern)?;
                    // 匹配到了URL
                    if let Some(url) = url_regex.find(annotation) {
                        let url_str = url.as_str().trim_matches('"');
                        let url_str = url_str.replace("\"", "").replace(" ", "").replace("value=", "");
                        // 可能重复命中类上的注解
                        if url_str.eq(&prefix) {
                            continue;
                        }
                        // 拼接类路由前缀
                        let mut url = url_str.to_string();
                        if !url.starts_with("/") {url.insert(0, '/');}
                        url.insert_str(0, &prefix);
                        interfaces.push(url);
                    }
                }
            }
        }
        Ok(interfaces)
    }

    /**
     * @descript 收集Struts接口信息
     * @param word_dir 要进行扫描的项目目录
     * @ note Struts url是由package的name属性加上action的name和method属性组成
     */
    pub fn collection_struts(work_dir: &str) -> Result<Interfaces, Box<dyn Error>> {
        let mut interfaces: Interfaces  = vec![];
        let xml_files = FileUtil::collection_file(work_dir, &vec!["xml".to_string()], &vec![])?;
        // 过滤出包含Struts的xml
        let struts_xml_files = xml_files.iter().filter(|xml_file|{
            match fs::read_to_string(xml_file) {
                Ok(content) => content.contains("<struts>"),
                Err(_) => false,
            }
        });
        // 遍历进行提取url
        for config_xml_path in struts_xml_files {
            let xml_data = fs::read_to_string(&config_xml_path)?;
            if xml_data.is_empty(){
                println!("[*]Struts配置文件{:?}是空的", config_xml_path);
                continue;
            }
    
            // 使用 xmltree 库将 XML 字符串解析为 Element
            let config_element = Element::parse(xml_data.as_bytes())?;
            for element in config_element.children.iter() {
                if let Some(root_element) = element.as_element(){
                    // 检查package标签
                    if root_element.name == "package" {
                        let namespace = root_element.attributes.get("name").unwrap();
                        // 获取pack下的所有action节点
                        let action_list = root_element.children.iter().filter(|e| {
                            match e.as_element() {
                                Some(element) => element.name.eq("action"),
                                None => false,
                            }
                        });
                        // 获取每一个action中的信息
                        for action_element in action_list {
                            if let Some(action_ele) = action_element.as_element() {
                                let method = action_ele.attributes.get("method");
                                let action_name = action_ele.attributes.get("name");
                                if method.is_none() || action_name.is_none() {
                                    continue;
                                }
                                let url = format!("{}/{}!{}.do", namespace, action_name.unwrap(), method.unwrap());
                                interfaces.push(url);
                            }
                        }
                    }
                }
            }
        }
        Ok(interfaces)
    }
    

    /**
     * 收集Struts2接口信息
     */
    fn collection_struts2(work_dir: &str) -> Result<Interfaces, Box<dyn Error>> {
        let mut interfaces: Interfaces = vec![];
        let xml_files = FileUtil::collection_file(work_dir, &vec!["xml".to_string()], &vec![])?;

        // 过滤出包含Struts的xml
        let struts_xml_files = xml_files.iter().filter(|xml_file|{
            match fs::read_to_string(xml_file) {
                Ok(content) => content.contains("<struts>"),
                Err(_) => false,
            }
        });

        for config_xml_path in struts_xml_files {
            let xml_data = fs::read_to_string(&config_xml_path)?;
            if xml_data.is_empty() {
                println!("[*]Struts2配置文件{:?}是空的", config_xml_path);
                continue;
            }

            // 使用 xmltree 库将 XML 字符串解析为 Element
            let config_element = Element::parse(xml_data.as_bytes())?;
            for element in config_element.children.iter() {
                if let Some(root_element) = element.as_element() {
                    // 检查package标签
                    if root_element.name == "package" {
                        // namespace可为空
                        let namespace = match root_element.attributes.get("namespace") {
                            Some(namespace) => namespace.to_owned(),
                            None => String::new(),
                        };
                        // 获取pack下的所有action节点
                        let action_list = root_element.children.iter().filter(|e| {
                            e.as_element().map_or(false, |element| element.name == "action")
                        });

                        // 获取每一个action中的信息
                        for action_element in action_list {
                            if let Some(action_ele) = action_element.as_element() {
                                let method = action_ele.attributes.get("method");
                                let name = match action_ele.attributes.get("name") {
                                    Some(name) => name.to_owned(),
                                    None => String::new(),
                                };
                                if method.is_none() {
                                    continue;
                                }
                                let url = format!("{}/{}/{}.action", namespace, name, method.unwrap());

                                interfaces.push(url);
                            }
                        }
                    }
                }
            }
        }
        Ok(interfaces)
    }

    fn collection_jsp(root: Vec<String>, _prefix_dir: &str) -> Result<Interfaces, Box<dyn Error>> {
        let mut jsp_list: Interfaces = vec![];

        // 遍历全部的jsp文件
        for file in root {
            if file.ends_with(".jsp") {
                // 把jsp页面项目的前缀去掉
                jsp_list.push(file.replace(_prefix_dir, ""));
                // jsp_list.push(file);
            }
        }

        Ok(jsp_list)
    }

    /**
     * @description 收集接口信息(java语言)，主要是扫描web.xml
     * @param root 项目根目录
     * @return Vec<String> 接口集合
     */
    fn collection_java_interface(root: &str, report_file: &mut File) -> Result<Vec<String>, Box<dyn Error>> {
        let xml_files = FileUtil::collection_file(root, &vec!["web.xml".to_string()], &vec![])?;
        let web_xml = match xml_files.get(0) {
            Some(web_xml_path) => Some(web_xml_path),
            None => None,
        };
        if web_xml.is_none() {
            println!("[-]web.xml文件未找到,skip");
            return Ok(vec![])
        }
        let web_xml = web_xml.unwrap();
        let xml = fs::read_to_string(web_xml)?;
        let webapp: Option<Element> = match Element::parse(xml.as_bytes()){
            Ok(web_app) => Some(web_app),
            Err(_) =>  { 
                println!("web.xml解析失败");
                None
            },
        };
        if webapp.is_none() {
            return Ok(vec![]) 
        }
        let mut webapp = webapp.unwrap();
        // 开始解析servlet
        let mut servlet_url_list: Vec<String> = Vec::new();

        println!("[+]开始查找servlet");
        report_file.write("web.xml关键信息:   \n```\n".as_bytes())?;
        // 找到servlet映射url
        while let Some(mut servlet_mapping) = webapp.take_child("servlet-mapping") {
            let mut servlet_class = Vec::new();
            // 存储url映射处理类
            while let Some(servlet_name) = servlet_mapping.take_child("servlet-name") {
                let name = &servlet_name.get_text().unwrap();
                Self::find_servlet_class_by_name(&webapp, "servlet", "servlet-class", "servlet-name", name, &mut servlet_class);
                report_file.write(
                    format!("[Servlet]: {} [Class] {:?}", name, servlet_class).as_bytes()
                )?;
            }
            // 存储url映射路径
            while let Some(url_pattern) = servlet_mapping.take_child("url-pattern") {
                let servlet_url = url_pattern.get_text().unwrap();
                report_file.write(
                    format!(" [URL]: {}  \n", servlet_url).as_bytes()
                )?;
                // println!("\t\t[-]映射到url: {}", servlet_url);
                servlet_url_list.push(servlet_url.to_string())
            }
        }
        // 开始解析过滤器
        Self::find_filters(&webapp, &webapp, report_file);
        report_file.write("\n```\n".as_bytes())?;
        Ok(servlet_url_list)
    }

    /**
     * @description 查找
     */
    fn find_servlet_class_by_name<'a>(element: &'a Element, tag: &str, find_tag: &str, tag_name: &str, tag_val: &str, results: &mut Vec<String>) {
        if element.name == tag {
            if let Some(servlet_name_element) = element.get_child(tag_name) {
                if let Some(servlet_name_val) = servlet_name_element.get_text() {
                    if servlet_name_val.eq(tag_val) {
                        if let Some(servlet_class_element) = element.get_child(find_tag) {
                            if let Some(servlet_class) = servlet_class_element.get_text() {
                                results.push(servlet_class.to_string());
                            }
                        }
                    }
                }
            }
        }
    
        for child in &element.children {
            if let Some(child) = child.as_element() {
                Self::find_servlet_class_by_name(child, tag, find_tag, tag_name, tag_val, results);
            }
        }
    }

    /**
     * @descript 找到所有的filter名，应用匹配路由和全路径类名
     * @param root 根xml
     * @param element 递归传递的参数
     */
    fn find_filters(root: &Element, element: &Element, report_file: &mut File) {
        if element.name == "filter" {
            let mut url_pattern = String::new();
            let mut filter_class = String::new();
    
            if let Some(filter_name_element) = element.get_child("filter-name") {
                if let Some(filter_name) = filter_name_element.get_text() {
                    
                    // 需要用到根xml
                    if let Some(filter_mapping_element) = root.get_child("filter-mapping") {
                        if let Some(url_pattern_element) = filter_mapping_element.get_child("url-pattern") {
                            // println!("pattern{:?}", url_pattern_element);
                            if let Some(pattern) = url_pattern_element.get_text() {
                                url_pattern = pattern.to_string();
                            }
                        }
                    }
                    // 递归查找过滤器类
                    if let Some(filter_class_element) = element.get_child("filter-class") {
                        if let Some(class) = filter_class_element.get_text() {
                            filter_class = class.to_string();
                        }
                    }
                    report_file.write(
                        format!("[Filter]: [{}] [Class]: [{}] <=> [URL]: [{}]  \n", filter_name, filter_class, url_pattern).as_bytes()
                    ).unwrap();
                }
            }
        }
    
        for child in &element.children {
            if let Some(child) = child.as_element() {
                Self::find_filters(root, child, report_file);
            }
        }
    }
}