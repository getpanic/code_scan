use std::{fs::File, io::{BufReader, BufRead, Write}, error::Error, sync::{mpsc::{channel, Sender}, Arc, Mutex}};

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use crate::{model::rule::Rule, enums::RuleCondition};
use lazy_static::lazy_static;

pub struct RuleCheck;

// 统计总行数
lazy_static! {
    // pub static ref TOTAL_LINE: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    pub static ref TOTAL_LINE: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    // 统计有效行数(除去空行)
    pub static ref NOT_NULL_LINE: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
}

impl RuleCheck{

    /**
     * @descript 获取命中规则的代码列表
     * @param rules 规则列表
     * @param path_list 要检查的源码文件路径列表
     * @param report_file 报告文件
     * @return 可能存在的错误
     */
    pub fn start(rules: &Vec<Rule>, path_list: Vec<String>, report_file: &mut File, use_ui: bool) -> Result<(), Box<dyn Error>> {
        report_file.write("### 根据规则扫描出的风险代码:   \n\n```\n".as_bytes())?;
        // 进度条计算
        let total_files = path_list.len() as u64;
        let progress_bar = ProgressBar::new(total_files);
        progress_bar.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")?
            .progress_chars("##-"));
        // 多生产单消费者
        let (tx, rx) = channel();
        let tx_shared = Arc::new(Mutex::new(tx));
        // 使用 rayon 的 par_iter 来并发地处理文件列表
        path_list.par_iter()
            .for_each(|file_path| {
                // 克隆 Arc<Mutex<Sender<String>>> 以供每个线程使用
                let tx_shared_clone = Arc::clone(&tx_shared);
                progress_bar.inc(1);
                if use_ui {
                    println!("{}/{}", progress_bar.position(), progress_bar.length().unwrap());
                }
                Self::check_file(rules, file_path, tx_shared_clone);
            });
    
        progress_bar.finish();

        // 关闭发送端，以便接收端知道不会再有更多的数据发送
        drop(tx_shared);

        // 继续处理接收端接收到的数据
        for received_data in rx {
            report_file.write(received_data.as_bytes())?;
        }
        report_file.write("\n```  \n\n".as_bytes())?;
        Ok(())
    }

    /**
     * @descript 检查规则是否命中
     * @param rules 规则列表
     * @param data 要进行检查的数据
     * @return (bool, String) 是否命中和命中的规则描述信息
     */
    fn rule_match_hit(rules: &Vec<Rule>, data: &str) -> (bool, String) {
        for rule in rules {
            match rule.condition {
                RuleCondition::Contain => {
                    if data.contains(&rule.keyword) {
                        // println!("hit {:?}", rule.keyword);
                        return (true, rule.note.clone())
                    }
                }
                RuleCondition::Regex => {
                    // 可能存在正则错误的情况
                    let regex = match Regex::new(&rule.keyword) {
                        Ok(re) => re,
                        Err(_) => panic!("请检查正则: [{}]是否是合法的表达式", rule.keyword),
                    };
                    if regex.is_match(data) {
                        // println!("hit {:?}", rule.keyword);
                        return (true, rule.note.clone())
                    }
                }
            }
        }
        return (false, String::new())
    }

    /**
     * @descript 检查文件是否命中规则，并将命中的信息通过发送者传递出去
     * @param rules 需要进行检查的规则列表
     * @param file_path 要进行检查的文件
     * @param sender 发送者
     */
    fn check_file(rules: &Vec<Rule>, file_path: &str, sender: Arc<Mutex<Sender<String>>>) {
        let mut matching_lines: Vec<String> = Vec::new();
        // let path = path_list.get(index).unwrap();
        let file = File::open(&file_path).unwrap();
        let lines = BufReader::new(file).lines();
        let mut cur_line = 0;
        let mut not_null_line = 0;

        lines.for_each(|line|{
            cur_line += 1;
            match line {
                Ok(line) => {
                    let trim_line = line.trim();
                    if trim_line.len() > 0 {
                        not_null_line += 1;
                        let (hit, description) = Self::rule_match_hit(&rules, &line);
                        if hit {
                            let format_result = format!("[-] 行[{}]命中风险代码:{:?},说明: [{}]  \n", cur_line, trim_line, description);
                            matching_lines.push(format_result);
                        }
                    }
                },
                Err(_) => {
                    // println!("文件[{}][{}]行内容读取失败: {}", path, cur_line, err)
                },
            }
        });

        // for line in lines {
        //     cur_line += 1;
        //     match line {
        //         Ok(line) => {
        //             let trim_line = line.trim();
        //             if trim_line.len() > 0 {
        //                 not_null_line += 1;
        //                 let (hit, description) = Self::rule_match_hit(&rules, &line);
        //                 if hit {
        //                     let format_result = format!("[-] 行[{}]命中风险代码:{:?},说明: [{}]  \n", cur_line, trim_line, description);
        //                     matching_lines.push(format_result);
        //                 }
        //             }
        //         },
        //         Err(_) => {
        //             // println!("文件[{}][{}]行内容读取失败: {}", path, cur_line, err)
        //         },
        //     }
        // }
        // 使用原子操作
        {
            *TOTAL_LINE.lock().unwrap() += cur_line;
            *NOT_NULL_LINE.lock().unwrap() += not_null_line;
        }
        // 当该文件至少有一行命中了规则
        if matching_lines.len() > 0 {
            let mut file_out = String::new();
            file_out.push_str(&format!("  \n  \n[!]文件[{}]找到可疑危险函数:  \n", file_path));
            sender.lock().unwrap().send(file_out).unwrap();
            for line in matching_lines {
                sender.lock().unwrap().send(format!(" {}\n", line)).unwrap();
            }
        }
    }
}