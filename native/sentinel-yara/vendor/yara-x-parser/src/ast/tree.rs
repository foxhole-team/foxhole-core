// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 FoxHole contributors.

use std::fmt::{self, Write};

pub(super) enum Tree {
    Node(String, Vec<Tree>),
    Leaf(Vec<String>),
}

pub(super) fn write_tree(output: &mut impl Write, tree: &Tree) -> fmt::Result {
    let mut pending = vec![(tree, String::from(" "), "", String::new())];
    while let Some((tree, prefix, branch, continuation)) = pending.pop() {
        match tree {
            Tree::Node(label, children) => {
                writeln!(output, "{prefix}{branch}{label}")?;
                let child_prefix = format!("{prefix}{continuation}");
                for (index, child) in children.iter().enumerate().rev() {
                    let last = index + 1 == children.len();
                    pending.push((
                        child,
                        child_prefix.clone(),
                        if last { "└─ " } else { "├─ " },
                        if last { "   " } else { "│  " }.to_owned(),
                    ));
                }
            }
            Tree::Leaf(lines) => {
                for (index, line) in lines.iter().enumerate() {
                    let edge = if index == 0 { branch } else { &continuation };
                    writeln!(output, "{prefix}{edge}{line}")?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Tree::*, write_tree};

    #[test]
    fn nested_multiline_leaves_keep_sibling_guides() {
        let tree = Node(
            "rule".into(),
            vec![
                Node("vars".into(), vec![Leaf(vec!["key".into(), "value".into()])]),
                Leaf(vec!["condition".into()]),
            ],
        );
        let mut output = String::new();
        write_tree(&mut output, &tree).unwrap();
        assert_eq!(output, " rule\n ├─ vars\n │  └─ key\n │     value\n └─ condition\n");
    }

    #[test]
    fn writer_errors_are_propagated() {
        struct Failed;
        impl std::fmt::Write for Failed {
            fn write_str(&mut self, _: &str) -> std::fmt::Result {
                Err(std::fmt::Error)
            }
        }
        assert!(write_tree(&mut Failed, &Leaf(vec!["rule".into()])).is_err());
    }
}
