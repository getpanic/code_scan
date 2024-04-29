use std::{error::Error, fs::File, path::PathBuf};

use enums::LangType;

use model::config::Config;

use project::{Application, JAVAProject, PHPProject, GOProject};

mod model;
mod util;
mod enums;
mod project;


fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::read_config_by_file()?;
    // 输出报告的文件，md格式
    if PathBuf::from(&config.report_file_path).exists() {
        panic!("报告文件: {} 已经存在", config.report_file_path);
    }
    let out_file = File::create(config.report_file_path.clone());
    if out_file.is_err() {
        panic!("报告文件: {} 创建失败", config.report_file_path);
    }
    let mut file = out_file?;
    // 根据语言加载
    match config.lang_type {
        LangType::JAVA => Application::<JAVAProject>::start(JAVAProject, config, &mut file),
        LangType::PHP => Application::<PHPProject>::start(PHPProject, config, &mut file),
        LangType::GO => Application::<GOProject>::start(GOProject, config, &mut file)
    }
}