use std::{fs, error::Error};

use walkdir::WalkDir;

use super::FileUtil;

impl FileUtil {
    /**
     * @descript 从路径读取文件，失败则返回空字符串
     * @param path 文件路径
     * @return String 文件内容字符串
     */
    pub fn read_file_by_path(path: &str) -> String{
        match fs::read(path) {
            Ok(binary) => {
                match String::from_utf8(binary) {
                    Ok(content) => content,
                    Err(_) => {
                        println!("文件[{}]不是utf8格式,读取失败", path);
                        String::new()
                    },
                }
            },
            Err(_) => {
                println!("文件[{}]读取失败", path);
                String::new()
            },
        }
    }

    /**
     * @descript 获取引入的文件的绝对路径
     * @param 配置路径 引入文件路径
    //  */
    // pub fn get_absolute_path(config_xml_path: &str, include_file: &str) -> Result<PathBuf, Box<dyn Error>> {
    //     let binding = PathBuf::from(config_xml_path);
    //     let config_xml_dir = binding.parent().unwrap();
    //     let include_path = Path::new(include_file);
    
    //     if include_path.is_absolute() {
    //         Ok(include_path.to_path_buf())
    //     } else {
    //         Ok(config_xml_dir.join(include_path))
    //     }
    // }

    /**
     * @description 收集需要扫描的文件
     * @param root_dir 要扫描的根级目录
     * @param exts 要扫描的文件后缀
     * @result Vec<String> 要扫描的文件绝对路径列表
     */
    pub fn collection_file(root_dir: &str, exts: &Vec<String>, exclude_path: &Vec<String>) -> Result<Vec<String>, Box<dyn Error>> {
        // 要扫描的文件path
        let mut paths: Vec<String> = Vec::new();

        for entry in WalkDir::new(root_dir) {
            let entry = entry?;
            if entry.path().is_file() {
                let fullpath = entry.path().display().to_string();
                for ext in exts {
                    if fullpath.ends_with(ext) {
                        paths.push(fullpath);
                        break;
                    }
                }
            }
        }

        paths = paths.into_iter().filter(|path| {
            for exclute in exclude_path {
                if path.contains(exclute) {
                    return false
                }
            }
            true
        }).collect();
        Ok(paths)
    }
}