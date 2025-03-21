# Pulsar-mel3
resource "openstack_compute_instance_v2" "pulsar-mel3" {
  name            = "pulsar-mel3"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.large"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

resource "openstack_compute_instance_v2" "pulsar-mel3-nfs" {
  name            = "pulsar-mel3-nfs"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.large"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

#Workers
resource "openstack_compute_instance_v2" "pulsar-mel3-w1" {
  name            = "pulsar-mel3-w1"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.xlarge"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

resource "openstack_compute_instance_v2" "pulsar-mel3-w2" {
  name            = "pulsar-mel3-w2"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.xlarge"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

resource "openstack_compute_instance_v2" "pulsar-mel3-w3" {
  name            = "pulsar-mel3-w3"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.xlarge"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

resource "openstack_compute_instance_v2" "pulsar-mel3-w4" {
  name            = "pulsar-mel3-w4"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.xxlarge"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

resource "openstack_compute_instance_v2" "pulsar-mel3-w5" {
  name            = "pulsar-mel3-w5"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.xxlarge"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

resource "openstack_compute_instance_v2" "pulsar-mel3-w6" {
  name            = "pulsar-mel3-w6"
  image_id        = "5a5ddeab-6655-444a-966d-e1d3223bde01"
  flavor_name     = "r3.xxlarge"
  key_pair        = "galaxy-australia"
  security_groups = ["SSH", "default"]
  availability_zone = "melbourne-qh2"
}

# Volume for pulsar-mel3
resource "openstack_blockstorage_volume_v3" "pulsar-mel3-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-app-volume"
  description = "Pulsar-mel3 application and job working directory volume"
  size        = 15000
}

resource "openstack_blockstorage_volume_v3" "pulsar-mel3-nfs-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-nfs-volume"
  description = "Pulsar-mel3 custom indices volume"
  size        = 3000
}

#Volumes for workers
resource "openstack_blockstorage_volume_v3" "pulsar-mel3-w1-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel2-w1-volume"
  description = "Pulsar-mel2 W1 volume"
  size        = 200
}

resource "openstack_blockstorage_volume_v3" "pulsar-mel3-w2-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-w2-volume"
  description = "Pulsar-mel3 W2 volume"
  size        = 200
}

resource "openstack_blockstorage_volume_v3" "pulsar-mel3-w3-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-w3-volume"
  description = "Pulsar-mel3 W3 volume"
  size        = 200
}

resource "openstack_blockstorage_volume_v3" "pulsar-mel3-w4-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-w4-volume"
  description = "Pulsar-mel3 W4 volume"
  size        = 200
}

resource "openstack_blockstorage_volume_v3" "pulsar-mel3-w5-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-w5-volume"
  description = "Pulsar-mel3 W5 volume"
  size        = 200
}

resource "openstack_blockstorage_volume_v3" "pulsar-mel3-w6-volume" {
  availability_zone = "melbourne-qh2"
  name        = "pulsar-mel3-w6-volume"
  description = "Pulsar-mel3 w6 volume"
  size        = 200
}

# Attachment between application/web server and volume
resource "openstack_compute_volume_attach_v2" "attach-mel3-volume-to-mel3" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-nfs-volume-to-mel3-nfs" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-nfs.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-nfs-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-w1-volume-to-mel3-w1" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-w1.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-w1-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-w2-volume-to-mel3-w2" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-w2.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-w2-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-w3-volume-to-mel3-w3" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-w3.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-w3-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-w4-volume-to-mel3-w4" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-w4.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-w4-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-w5-volume-to-mel3-w5" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-w5.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-w5-volume.id}"
}

resource "openstack_compute_volume_attach_v2" "attach-mel3-w6-volume-to-mel3-w6" {
  instance_id = "${openstack_compute_instance_v2.pulsar-mel3-w6.id}"
  volume_id   = "${openstack_blockstorage_volume_v3.pulsar-mel3-w6-volume.id}"
}
