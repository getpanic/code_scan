use std::{fs::{File, self}, error::Error, io::Write};

use regex::Regex;

use crate::{model::{config::Config, Interfaces}, util::{PathUtil, rule_check::RuleCheck, FileUtil}};

use super::{GOProject, Scanner};

impl Scanner for GOProject{

    fn start(&self, config: &mut Config, report_file: &mut File) -> Result<Interfaces, Box<dyn Error>>{
        let file_path_list: Vec<String> = FileUtil::collection_file(&config.work_dir, &config.scan_ext, &config.exclude_path)?;
        let mut file_list_info: String = String::from("### 根据后缀找到文件列表:   \n\n```\n");
        // 获取去掉前缀，只保留项目路径
        for file_path in &PathUtil::clear_prefix(file_path_list.clone(), &config.work_dir) {
            file_list_info.push_str(format!(" - {}", file_path).as_str())
        }
        file_list_info.push_str("\n```  \n\n");
        report_file.write(file_list_info.as_bytes())?;
        println!("[+]要扫描的文件收集完毕");
        let interface: Interfaces = GOProject::collection_interface(file_path_list.clone())?;
        // 根据扫描规则跑出来的漏洞
        RuleCheck::start(&config.rule, file_path_list, report_file, config.use_ui)?;
        println!("[+]基于规则漏洞扫描完毕");
        Ok(interface)
    }
}

impl GOProject {
    fn collection_interface(path_list: Vec<String>) -> Result<Interfaces, Box<dyn Error>> {
        let mut interfaces: Interfaces = vec![];

        let re = Regex::new(r#"router\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*"(.*?)"\s*,\s*(.*?)\)"#)?;

        // 遍历每个Go源码文件并提取路由信息
        path_list.into_iter().for_each(|path|{
            match fs::read_to_string(&path) {
                Ok(content) => {
                    for captures in re.captures_iter(&content) {
                        let http_method = captures.get(1).unwrap().as_str();
                        let url_path = captures.get(2).unwrap().as_str();

                        println!("HTTP Method: {}", http_method);
                        println!("URL Path: {}", url_path);
                        interfaces.push(url_path.to_string());
                    }
                },
                Err(_err) => println!("[-]读取文件{}失败!", path),
            }
        });
        Ok(interfaces)
    }
}