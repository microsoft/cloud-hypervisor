use std::ffi::CString;
use std::mem::size_of_val;
use device_tree::DeviceTree;
//use fdt_rs::common::prop;
use vm_fdt::{FdtWriter, FdtWriterResult, Error};

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
pub struct NodeBuilder {
    pub name: String,

    /// A list of node properties, `(key, value)`.
    pub props: Vec<(String, Vec<u8>)>,
}


impl NodeBuilder {
    #[allow(dead_code)]
    fn new(node_name: &str) -> NodeBuilder {
        let mut _props = Vec::new();
        NodeBuilder {
            name: node_name.to_string(),
            props: _props,
        }
    }
    #[allow(dead_code)]
    fn add_property(&mut self, prop_name: &str, value:  &[u8]) -> Result<()> {
        self.props.push((prop_name.to_string(), value.to_owned()));
        Ok(())
    }
    #[allow(dead_code)]
    /// Write an empty property.
    pub fn property_null(&mut self, name: &str) -> Result<()> {
        self.add_property(name, &[])
    }
    #[allow(dead_code)]
    /// Write a string property.
    pub fn property_string(&mut self, name: &str, val: &str) -> Result<()> {
        let cstr_value = CString::new(val).map_err(|_| Error::InvalidString)?;
        self.add_property(name, cstr_value.to_bytes_with_nul())
    }
    #[allow(dead_code)]
    /// Write a stringlist property.
    pub fn property_string_list(&mut self, name: &str, values: Vec<String>) -> Result<()> {
        let mut bytes = Vec::new();
        for s in values {
            let cstr = CString::new(s).map_err(|_| Error::InvalidString)?;
            bytes.extend_from_slice(cstr.to_bytes_with_nul());
        }
        self.add_property(name, &bytes)
    }
    #[allow(dead_code)]
    /// Write a 32-bit unsigned integer property.
    pub fn property_u32(&mut self, name: &str, val: u32) -> Result<()> {
        self.add_property(name, &val.to_be_bytes())
    }
    #[allow(dead_code)]
    /// Write a 64-bit unsigned integer property.
    pub fn property_u64(&mut self, name: &str, val: u64) -> Result<()> {
        self.add_property(name, &val.to_be_bytes())
    }
    #[allow(dead_code)]
    /// Write a property containing an array of 32-bit unsigned integers.
    pub fn property_array_u32(&mut self, name: &str, cells: &[u32]) -> Result<()> {
        let mut arr = Vec::with_capacity(size_of_val(cells));
        for &c in cells {
            arr.extend(&c.to_be_bytes());
        }
        self.add_property(name, &arr)
    }
    #[allow(dead_code)]
    /// Write a property containing an array of 64-bit unsigned integers.
    pub fn property_array_u64(&mut self, name: &str, cells: &[u64]) -> Result<()> {
        let mut arr = Vec::with_capacity(size_of_val(cells));
        for &c in cells {
            arr.extend(&c.to_be_bytes());
        }
        self.add_property(name, &arr)
    }
    #[allow(dead_code)]
    pub fn build(&self) -> device_tree::Node {

        device_tree::Node {
            name: self.name.clone(),
            props: self.props.clone(),
            children: Vec::new(),
        }
    }
}
#[allow(dead_code)]
pub fn copy_from_fdt_tree(dt: &DeviceTree) -> FdtWriterResult<Vec<u8>> {

    let mut writer = FdtWriter::new().unwrap();
    writer.set_boot_cpuid_phys(dt.boot_cpuid_phys);
    let root = writer.begin_node("")?;
    let dt_root = &dt.root;
    for prop in dt_root.props.iter() {
        let name = prop.0.clone();
        let value = prop.1.clone();
        writer.property(&name, &value)?;
    }
    for child in dt_root.children.iter() {
        add_node_writer(&mut writer, &child)?;
    }
    writer.end_node(root)?;
    return writer.finish()
}
#[allow(dead_code)]
fn add_node_writer(writer: &mut FdtWriter, node: &device_tree::Node) -> FdtWriterResult<()> {
    let child = writer.begin_node(&node.name)?;
    for prop in node.props.iter() {
        let name = prop.0.clone();
        let value = prop.1.clone();
        writer.property(&name, &value)?;
    }
    for nested_child in node.children.iter() {
        add_node_writer(writer, nested_child)?;
    }
    writer.end_node(child)?;
    Ok(())
}
#[allow(dead_code)]
fn find_parent_node<'a>(root: &'a mut device_tree::Node, name: &str) -> Option<&'a mut device_tree::Node>{

    if root.name == name {
        return None;
    }
    for child in &mut root.children.iter() {
        if child.name == name {
            return Some(root);
        }
    }
    for child in  &mut root.children {
        let ret = find_parent_node(child, name);
        if let Some(ch) = ret {
            return Some(ch);
        }
    }
    return None
}
#[allow(dead_code)]
pub fn find_parent<'a>(dt: &'a mut DeviceTree, name: &str) -> Option<&'a mut device_tree::Node>{
    return find_parent_node(&mut dt.root, name);
}
#[allow(dead_code)]
fn add_child(root: &mut device_tree::Node, child: device_tree::Node) {
    root.children.push(child);
}
#[allow(dead_code)]
fn create_vector_for_reg(acells: u32, adress: u64, scells: u32, size:u64) -> FdtWriterResult<Vec<u32> > {
    let ys: [u64; 4] = [acells.into(), adress, scells.into(), size];
    let mut propcells: Vec<u32> = Vec::with_capacity(ys.len()); 
    let mut value: u64;
    let mut cellnum: usize;
    let mut ncells: u32;
    let mut hival: u32;

    cellnum = 0;
    for vnum in 0..ys.len() {
        ncells = ys[vnum * 2] as u32;
        if ncells != 1 && ncells != 2 {
            return Err(Error::InvalidMemoryReservation);
        }
        value = ys[vnum * 2 + 1];
        hival = ((value >> 32) as u32).to_be();
        if ncells > 1 {
            propcells[cellnum] = hival;
            cellnum += 1;
        } else if hival != 0 {
            return Err(Error::InvalidMemoryReservation);
        }
        propcells[cellnum] = value.to_be() as u32;
    }
    return Ok(propcells)
}
#[allow(dead_code)]
pub fn edit_fdt_tree_with_writer(dt: &DeviceTree,node_name: &str, prop_name: &str, value: &Vec<u8> ) -> FdtWriterResult<Vec<u8>> {

    let mut writer = FdtWriter::new().unwrap();
    writer.set_boot_cpuid_phys(dt.boot_cpuid_phys);
    let root = writer.begin_node("")?;
    let dt_root = &dt.root;
    for prop in dt_root.props.iter() {
        let name = prop.0.clone();
        let value = prop.1.clone();
        writer.property(&name, &value)?;
    }
    for child in dt_root.children.iter() {
        edit_node_with_writer(&mut writer, &child, node_name, prop_name, value)?;
    }
    writer.end_node(root)?;
    return writer.finish()
}
#[allow(dead_code)]
pub fn edit_node_with_writer(writer: &mut FdtWriter, node: &device_tree::Node, node_name: &str, prop_name: &str, new_value: &Vec<u8> ) -> FdtWriterResult<()> {
    let child = writer.begin_node(&node.name)?;
    for prop in node.props.iter() {

        let name = prop.0.clone();
        
        if node.name == node_name && name == prop_name {
            writer.property(&name, &new_value)?;
        } else {
            let value = prop.1.clone();
            writer.property(&name, &value)?;
        }
    }
    for nested_child in node.children.iter() {
        edit_node_with_writer(writer, nested_child, node_name, prop_name, new_value)?;
    }
    writer.end_node(child)?;
    Ok(())
}
#[allow(dead_code)]
pub fn modify_prop_regs(dt: &DeviceTree, node_name: &str, prop_name: &str, acells: u32, adress: u64, scells: u32, size:u64) -> FdtWriterResult<Vec<u8>>  {
    let new_val = create_vector_for_reg(acells,adress,scells, size)?;
    let mut arr = Vec::with_capacity(size_of_val(&new_val));
    for c in new_val.iter() {
        arr.extend(&c.to_be_bytes());
    }
    edit_fdt_tree_with_writer(dt,node_name,prop_name, &arr)
}

fn edit_node_int(node: &mut device_tree::Node, prop_name: &str, new_value: &Vec<u32>) -> FdtWriterResult<()> {
    let mut arr = Vec::with_capacity(size_of_val(new_value));
    for &c in new_value {
        arr.extend(&c.to_be_bytes());
    }
    for prop in node.props.iter_mut() {
        if prop.0 == prop_name {
            prop.1 = arr.clone();
        }
    }
    Ok(())
}
#[allow(dead_code)]
pub fn edit_fdt_tree(dt: &mut DeviceTree,node_name: &str, prop_name: &str, value: &Vec<u32> ) -> FdtWriterResult<()> {
    let opt_node = find_node(dt, node_name);
    if let Some(node) = opt_node {
        edit_node_int(node, prop_name, value)?
    }
    Ok(())
}
fn find_node_util<'a>(root: &'a mut device_tree::Node, name: &str) -> Option<&'a mut device_tree::Node> {
    if root.name == name {
        return Some(root);
    }
    for child in &mut root.children  {
        if let Some(ret) = find_node_util(child, name) {
            return Some(ret)
        }
    }

    return None
}
#[allow(dead_code)]
pub fn find_node<'a>(dt: &'a mut DeviceTree, name: &str) -> Option<&'a mut device_tree::Node>{

    return find_node_util(&mut dt.root, name);
}