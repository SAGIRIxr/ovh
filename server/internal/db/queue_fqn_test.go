package db

import (
	"github.com/ovh-buy/server/internal/types"
	"testing"
)

func TestQueueFQNSurvivesRestartAndMigration(t *testing.T) {
	dir := t.TempDir()
	database, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const fqn = "27skleb01-v1.ram-32g-ecc-2400.softraid-2x450nvme"
	if err := database.ReplaceQueue([]types.QueueItem{
		{ID: "pinned", PlanCode: "27skleb01-v1", Datacenter: "gra", Status: "running", FQN: fqn},
		{ID: "plain", PlanCode: "24sk202", Datacenter: "rbx", Status: "running"},
	}); err != nil {
		t.Fatal(err)
	}
	database.Close()
	database, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := database.ListQueue()
	if err != nil || len(got) != 2 {
		t.Fatalf("list queue: %+v %v", got, err)
	}
	for _, q := range got {
		if q.FQN != map[string]string{"pinned": fqn}[q.ID] {
			t.Fatalf("fqn lost or applied to another task: %+v", q)
		}
	}

	// 老库没有 fqn 列:迁移补列后已有任务原样保留
	if _, err := database.Exec("ALTER TABLE queue DROP COLUMN fqn"); err != nil {
		t.Fatal(err)
	}
	database.Close()
	database, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	got, err = database.ListQueue()
	if err != nil || len(got) != 2 || got[0].FQN != "" || got[1].FQN != "" {
		t.Fatalf("legacy queue changed during fqn migration: %+v %v", got, err)
	}
}
