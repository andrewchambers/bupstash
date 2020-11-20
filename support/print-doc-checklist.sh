

cat <<EOF
[ ] Documentation
  [ ] Command man pages
EOF

for md in $(echo doc/man/*.1.md)
do
cat <<EOF
    [ ] $md
      [ ] proof read.
      [ ] flags match equivalent source code file.
      [ ] examples match equivalent doc/cli/* file.
      [ ] doc/cli/* file rendering looks good in terminal.
      [ ] examples are correct and working.
      [ ] passes spell check.
      [ ] No visual anomalies when rendered on website.
      [ ] No visual anomalies when rendered on website with mobile.
      [ ] No visual anomalies when rendered by 'man'.
EOF
done
