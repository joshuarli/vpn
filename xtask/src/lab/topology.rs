pub struct Topology {
    pub client_ns: &'static str,
    pub server_ns: &'static str,
    pub client_dev: &'static str,
    pub server_dev: &'static str,
    pub client_addr: &'static str,
    pub server_addr: &'static str,
    pub prefix: u8,
}

pub const LAB: Topology = Topology {
    client_ns: "c",
    server_ns: "s",
    client_dev: "vc",
    server_dev: "vs",
    client_addr: "10.77.0.1",
    server_addr: "10.77.0.2",
    prefix: 24,
};

impl Topology {
    pub fn teardown_script(&self) -> String {
        format!(
            "ip netns del {c} 2>/dev/null || true\nip netns del {s} 2>/dev/null || true\n",
            c = self.client_ns,
            s = self.server_ns
        )
    }

    pub fn setup_script(&self, veth_mtu: u32) -> String {
        let mut script = String::new();
        // Docker mounts /proc/sys read-only; twice writes sysctls inside the namespaces.
        script.push_str("mount -o remount,rw /proc/sys 2>/dev/null || true\n");
        script.push_str("mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200\n");
        script.push_str(&self.teardown_script());
        script.push_str(&format!(
            "ip netns add {c}\nip netns add {s}\n\
             ip link add {cd} netns {c} type veth peer name {sd} netns {s}\n\
             ip -n {c} addr add {ca}/{p} dev {cd}\nip -n {s} addr add {sa}/{p} dev {sd}\n\
             ip -n {c} link set lo up\nip -n {s} link set lo up\n\
             ip -n {c} link set {cd} mtu {m} up\nip -n {s} link set {sd} mtu {m} up\n\
             ip -n {c} route add default via {sa}\nip -n {s} route add default via {ca}\n",
            c = self.client_ns,
            s = self.server_ns,
            cd = self.client_dev,
            sd = self.server_dev,
            ca = self.client_addr,
            sa = self.server_addr,
            p = self.prefix,
            m = veth_mtu
        ));
        script
    }

    pub fn netem_script(&self, spec: &str) -> String {
        format!(
            "ip netns exec {c} tc qdisc replace dev {cd} root netem {spec}\n\
             ip netns exec {s} tc qdisc replace dev {sd} root netem {spec}\n",
            c = self.client_ns,
            s = self.server_ns,
            cd = self.client_dev,
            sd = self.server_dev
        )
    }

    pub fn clear_netem_script(&self) -> String {
        format!(
            "ip netns exec {c} tc qdisc del dev {cd} root 2>/dev/null || true\n\
             ip netns exec {s} tc qdisc del dev {sd} root 2>/dev/null || true\n",
            c = self.client_ns,
            s = self.server_ns,
            cd = self.client_dev,
            sd = self.server_dev
        )
    }
}
