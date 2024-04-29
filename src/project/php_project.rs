use std::{fs::{File, self}, error::Error, io::Write};

use regex::Regex;

use crate::{util::{PathUtil, rule_check::RuleCheck, FileUtil}, model::{config::Config, Interfaces}, enums::Framwork::*};

use super::{Scanner, PHPProject};

impl Scanner for PHPProject {
    fn start(&self, config: &mut Config, report_file: &mut File) -> Result<Vec<String>, Box<dyn Error>>{
        // 要扫描的代码文件后缀路径收集
        let file_path_list: Vec<String> = FileUtil::collection_file(&config.work_dir, &config.scan_ext, &config.exclude_path)?;
        let mut file_list_info: String = String::from("### 根据后缀找到文件列表:   \n\n```\n");
        // 获取去掉前缀，只保留项目路径
        for file_path in &PathUtil::clear_prefix(file_path_list.clone(), &config.work_dir) {
            file_list_info.push_str(format!(" - {}\n", file_path).as_str())
        }
        file_list_info.push_str("\n```  \n\n");
        report_file.write(file_list_info.as_bytes())?;
        // 接口收集
        let interfaces: Interfaces = PHPProject::collection_interface(&config, file_path_list.clone(), report_file)?;
        // println!("interface: {:?}", interfaces);
        // 根据扫描规则跑出来的漏洞
        RuleCheck::start(&config.rule, file_path_list, report_file, config.use_ui)?;
        println!("[+]基于规则漏洞扫描完毕");
        Ok(interfaces)
    }
}

impl PHPProject {

    /**
     * @descript 收集接口
     * @param config 配置对象
     * @param 要扫描的文件绝对路径地址列表
     */
    fn collection_interface(config: &Config, file_path_list: Vec<String>, report_file: &mut File) -> Result<Interfaces, Box<dyn Error>>{
        let mut interfaces: Interfaces = Vec::new();
        // 配置选择了收集接口
        if config.collection_interface {
            // 框架代码选择
            let mut framework_interface: Interfaces = match config.framework {
                Laravel => Self::collection_laravel_interface(file_path_list.clone())?,
                ThinkPhp => Self::collection_thinkphp_interface(file_path_list.clone())?,
                None => {
                    println!("未使用开发框架，跳过特定检查");
                    vec![]
                },
                _ => panic!("配置中填写的框架非php框架,请检查配置文件!")
            };
            // 收集原生的web处理php文件
            interfaces.append(&mut framework_interface);
            interfaces.append(&mut Self::collection_request_php(file_path_list)?);
            report_file.write(format!("### 扫描出的接口列表:   \n```\n{:#?}\n```\n", interfaces).as_bytes())?;
            println!("[+]接口地址收集完毕");
        }
        println!("[+]要扫描的文件收集完毕");
        Ok(interfaces)
    }

    /**
     * @descript 从laravel框架中提取url
     * @param 要扫描的文件列表
     * @return laravel框架的接口
     */
    fn collection_laravel_interface(file_path_list: Vec<String>) -> Result<Interfaces, Box<dyn Error>>{
        let mut extracted_urls: Interfaces = Vec::new();

        // 遍历查找接口
        for php_file in file_path_list {
            let php_code = String::from_utf8(fs::read(php_file)?)?;
            let lines = php_code.lines().collect::<Vec<_>>();
            let mut base_prefix = String::new();

            for line in lines {
                if let Some(prefix_capture) = line.strip_prefix("Route::prefix('") {
                    if let Some(prefix) = prefix_capture.split('\'').next() {
                        base_prefix.push_str(prefix);
                    }
                } else if line.contains("Route::get('") {
                    if let Some(url) = line.split("Route::get('").nth(1) {
                        if let Some(end_quote) = url.find('\'') {
                            let url_segment = &url[..end_quote];
                            let full_url = format!("{}/{}", base_prefix, url_segment);
                            extracted_urls.push(full_url);
                        }
                    }
                } else if line.contains("Route::group(") {
                    base_prefix = String::new();
                }
            }
        }

        Ok(extracted_urls)
    }

    /**
     * @descript 从thinkphp提取接口地址
     * @param 要扫描的文件列表
     * @return thinkphp框架的接口地址
     */
    fn collection_thinkphp_interface(file_path_list: Vec<String>) -> Result<Interfaces, Box<dyn Error>> {
        println!("[+]开始提取ThinkPHP框架接口");
        let mut interface_list: Interfaces = vec![];
    
        // 遍历查找接口
        for php_file in file_path_list.clone() {
            let php_code = match fs::read_to_string(&php_file) {
                Ok(source_code) => source_code,
                Err(err) => {
                    println!("[-]文件: {}读取失败,msg: {:?}", php_file, err);
                    continue;
                },
            };
            let route_regex = Regex::new(r#"(Route::(?:get|post|put|delete|any)\(['"]([^'"]*?)['"]|Route::prefix\(['"]([^'"]*?)['"]\)\s*->\s*group\(\s*\)\s*|Route::group\s*\(\s*\)\s*|})"#)?;
    
            // 查找匹配的路由地址
            for capture in route_regex.captures_iter(&php_code) {
                if let Some(url) = capture.get(2) {
                    interface_list.push(url.as_str().to_string());
                } else if let Some(prefix) = capture.get(3) {
                    if capture.get(1).unwrap().as_str() == "prefix" {
                        interface_list.push(prefix.as_str().to_string());
                    }
                } else if capture.get(0).unwrap().as_str() == "}" {
                    interface_list.pop();
                }
            }
        }

        // 先收集application下的文件
        let application_files = file_path_list.into_iter().filter(|path|{
            path.contains("/application/")
        });

        // 直接继承自Controller的文件接口
        application_files.into_iter().for_each(|path|{
            let php_code = match fs::read_to_string(&path) {
                Ok(source_code) => source_code,
                Err(err) => {
                    println!("[-]{}文件: {}读取失败,msg: {:?}",line!(), path, err);
                    String::new()
                },
            };
            // 源码不为空
            if !php_code.is_empty() {
                let controller_regex = Regex::new(r"\bclass\s+([A-Z]\w*)\s+extends\s+Controller\b").unwrap();
                // 当捕捉到是一个继承了Controller的接口文件
                if let Some(captures) = controller_regex.captures(&php_code) {
                    if let Some(_class_name) = captures.get(1) {
                        let mut prefix = String::new();
                        // 提取类名
                        // let class_name = class_name.as_str();
                        let pattern = r"application/([a-zA-Z]+)/controller/([a-zA-Z]+)\.php";
                        let re = Regex::new(pattern).unwrap();
                        // 提取模块名和控制器名拼接接口地址
                        if let Some(captures) = re.captures(&path) {
                            let module = captures.get(1).map_or("", |m| m.as_str());
                            let controller = captures.get(2).map_or("", |m| m.as_str());
                            prefix.push_str(&format!("/{}/{}", module, controller.replace("Controller", "")).to_lowercase());
                        }
                        // 当前缀不为空
                        if !prefix.is_empty(){
                            // 提取后缀的方法名
                            let method_regex = Regex::new(r"\bpublic\s+function\s+([A-Za-z_]\w*)\s*\(").unwrap();
                            for method_captures in method_regex.captures_iter(&php_code) {
                                if let Some(method_name) = method_captures.get(1) {
                                    let method_name = method_name.as_str();
                                    // 不记录构造函数
                                    if !method_name.eq("__construct"){
                                        interface_list.push(format!("{}/{}", prefix, method_name))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        println!("[+]ThinkPHP框架接口信息提取完毕");
        Ok(interface_list)
    }

    /**
     * @descript 从php文件中提取出原生会接受请求参数的文件
     * @param 要扫描的文件列表
     * @return 收集到的会处理请求的php文件
     */
    fn collection_request_php(file_path_list: Vec<String>) -> Result<Interfaces, Box<dyn Error>>{
        Ok(file_path_list.into_iter().filter(|file_path|{
            let file_content = fs::read_to_string(&file_path);
            if file_content.is_err() {return false;}
            let file_content = file_content.unwrap();
            file_content.contains("$_GET") || file_content.contains("$_POST") || file_content.contains("$_REQUEST")
        }).collect())
    }
}