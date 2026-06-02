use anyhow::Result;

pub fn change_boot_order(boot_order: &[u16], target_id: u16) -> Result<Vec<u16>> {
    let mut new_order = boot_order.to_vec();
    
    if let Some(index) = new_order.iter().position(|&id| id == target_id) {
        let item = new_order.remove(index);
        new_order.insert(0, item);
    } else {
        new_order.insert(0, target_id);
    }
    
    Ok(new_order)
}