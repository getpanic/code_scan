use super::PathUtil;

impl PathUtil {
    pub fn clear_prefix(list: Vec<String>, prefix: &str) -> Vec<String>{
        list
            .iter()
            .map(|item| item.replace(prefix, ""))
            .collect()
    }
}