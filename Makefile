BASE=registry.suse.com/cap/scf-diego-cell
BASETAG=735bec6bc52438a4b73b670ad4a4c2959b82ae69

TAG=bugzilla-11917460-extended-logging
DEV=registry.hub.docker.com/a99k/scf-diego-cell

gdn:
	go build -o "$(abspath $@)" -mod vendor -tags daemon -ldflags "-X main.version=dev-$(TAG)" ./cmd/gdn

vet:
	go vet -mod vendor ./cmd/gdn ./kawasaki

image: Dockerfile gdn
	docker build -t $(DEV):$(BASETAG)-$(TAG) .
	docker push     $(DEV):$(BASETAG)-$(TAG)

suse: Dockerfile gdn
	docker build -t $(BASE):$(BASETAG)-$(TAG) .
	docker push     $(BASE):$(BASETAG)-$(TAG)

.PHONY: gdn
