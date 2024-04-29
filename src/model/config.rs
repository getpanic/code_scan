use std::{error::Error, fs, path::Path};

use serde::Deserialize;

use crate::enums::{LangType, Framwork, ORM};

use super::{rule::Rule, unauthorized::Unauthorized};

/**
 * @Sturuct Config 配置类加载
 * @Field lang_type 要扫描的语言类型
 * @Field work_dir 要扫描的目录
 * @Field scan_ext 要扫描的文件后缀
 * @Field exclute_path 不扫描的目录
 * @Field collection_interface 是否尝试收集接口信息
 * @Field framework 使用的框架名
 * @Field orm 使用了什么ORM框架
 * @Field depency_file 第三方依赖配置文件
 * @Feild unauthorized 是否要进行未授权扫描
 * @Field rule 加载的扫描规则 
 * @Field use_ui 默认为不使用
 */
#[derive(Deserialize, Debug)]
pub struct Config{

    pub project_name: String,

    pub lang_type: LangType,

    pub work_dir: String,

    pub exclude_path: Vec<String>,

    pub scan_ext: Vec<String>,

    pub collection_interface: bool,

    pub framework: Framwork,

    pub orm: ORM,

    pub depency_file: String,

    pub unauthorized: Unauthorized,

    pub report_file_path: String,

    pub use_ui: bool,

    #[serde(default = "empty_rule")]
    pub rule: Vec<Rule>,

}

impl Config{

    /**
     * @descript 从文件读取配置信息
     * @return 加载后的Config对象
     */
    pub fn read_config_by_file() -> Result<Self, Box<dyn Error>>{
        let programer = std::env::current_exe()?;
        let parent = programer.parent().unwrap();
        // 读取同级目录的config.json
        let config_path = parent.join("config.json");
        if config_path.is_file() {
            match fs::read_to_string(&config_path) {
                Ok(json_string) => {
                    let config = serde_json::from_str::<Self>(&json_string);
                    if config.is_err() { panic!("[-]配置文件格式有错误,请检查配置文件格式"); }
                    let mut config = config?;
                    if !Path::new(&config.report_file_path).is_absolute() {
                        config.report_file_path = parent.join(config.report_file_path).to_string_lossy().to_string();
                    }
                    return Ok(config)
                },
                Err(_) => panic!("[-]配置文件{}不存在！读取失败", config_path.display()),
            };
        } else {
            panic!("[-]配置文件{}不存在", config_path.display());
        }

    }

    /**
     * @descript 从配置文件中读取规则加载
     * @param self Config对象
     */
    pub fn load_rule(&mut self) -> Result<(), Box<dyn Error>>{
        let programer = std::env::current_exe()?;
        let parent = programer.parent().unwrap();
        let rule_file = match self.lang_type {
            LangType::JAVA => "rules/java.json",
            LangType::PHP => "rules/php.json",
            LangType::GO => "rules/go.json",
        };
        let rule_file = parent.join(rule_file);
        println!("[*]开始读取规则文件：{:?}", rule_file);
        match fs::read_to_string(&rule_file) {
            Ok(rule_json) => {
                let rule = serde_json::from_str::<Vec<Rule>>(&rule_json);
                if rule.is_err() { panic!("[-]请检查规则文件格式"); }
                self.rule = rule?
            },
            Err(_) => panic!("[-]规则文件{}不存在！读取失败", rule_file.display()),
        };
        Ok(())
    }

}

// 初始化规则
pub fn empty_rule() -> Vec<Rule>{
    vec![]
}