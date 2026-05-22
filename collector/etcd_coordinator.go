package main

import (
	"context"
	"log"
	"sort"
	"time"

	"github.com/google/uuid"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	etcdKeyPrefix = "/lab14/collectors/"
	leaseTTLSec   = 10
)

// EtcdCoordinator регистрирует этот инстанс сборщика в etcd
// и распределяет PCAP-файлы по шардам между всеми живыми инстансами.
type EtcdCoordinator struct {
	client     *clientv3.Client
	instanceID string
	leaseID    clientv3.LeaseID
	cancelKA   context.CancelFunc // отменяет keep-alive горутину
}

// NewEtcdCoordinator создаёт клиент etcd и возвращает координатор.
func NewEtcdCoordinator(endpoints []string) (*EtcdCoordinator, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &EtcdCoordinator{
		client:     cli,
		instanceID: uuid.New().String(),
	}, nil
}

// Register получает lease и публикует ключ этого инстанса в etcd.
// Keep-alive поддерживает lease живым до вызова Close().
func (c *EtcdCoordinator) Register(ctx context.Context) error {
	resp, err := c.client.Grant(ctx, leaseTTLSec)
	if err != nil {
		return err
	}
	c.leaseID = resp.ID

	key := etcdKeyPrefix + c.instanceID
	if _, err = c.client.Put(ctx, key, c.instanceID, clientv3.WithLease(c.leaseID)); err != nil {
		return err
	}

	// Keep-alive в фоне — поддерживает lease до отмены контекста.
	kaCtx, cancel := context.WithCancel(context.Background())
	c.cancelKA = cancel
	kaCh, err := c.client.KeepAlive(kaCtx, c.leaseID)
	if err != nil {
		cancel()
		return err
	}
	go func() {
		for range kaCh {
		} // вычитываем ответы keep-alive, чтобы не заблокировать etcd клиент
	}()

	log.Printf("[ETCD] зарегистрирован: instance=%s lease=%x", c.instanceID, c.leaseID)
	return nil
}

// GetShard возвращает подмножество files, закреплённое за этим инстансом.
//
// Алгоритм: список всех живых инстансов сортируется → определяется индекс
// этого инстанса → каждый i-й файл (i % n == myIndex) отдаётся этому шарду.
// Если etcd недоступен или инстанс не найден — возвращаются все файлы
// (безопасный fallback для однонодового запуска).
func (c *EtcdCoordinator) GetShard(ctx context.Context, files []string) ([]string, error) {
	resp, err := c.client.Get(ctx, etcdKeyPrefix, clientv3.WithPrefix())
	if err != nil {
		log.Printf("[ETCD] не удалось получить список инстансов: %v — обрабатываю все файлы", err)
		return files, nil
	}

	// Собираем и сортируем ID всех инстансов для детерминированного порядка.
	instances := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		instances = append(instances, string(kv.Value))
	}
	sort.Strings(instances)

	myIndex := -1
	for i, id := range instances {
		if id == c.instanceID {
			myIndex = i
			break
		}
	}
	if myIndex < 0 {
		log.Printf("[ETCD] инстанс не найден в списке — обрабатываю все файлы")
		return files, nil
	}

	n := len(instances)
	sort.Strings(files) // детерминированный порядок файлов

	var shard []string
	for i, f := range files {
		if i%n == myIndex {
			shard = append(shard, f)
		}
	}

	log.Printf("[ETCD] шард %d/%d: %d из %d файлов", myIndex+1, n, len(shard), len(files))
	return shard, nil
}

// Close отзывает lease (ключ удаляется немедленно) и закрывает клиент.
func (c *EtcdCoordinator) Close() {
	if c.cancelKA != nil {
		c.cancelKA()
	}
	if c.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if c.leaseID != 0 {
			if _, err := c.client.Revoke(ctx, c.leaseID); err != nil {
				log.Printf("[ETCD] ошибка revoke lease: %v", err)
			}
		}
		c.client.Close()
	}
	log.Println("[ETCD] соединение закрыто")
}
