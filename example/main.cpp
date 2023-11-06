#include <git2.h>

#include <iostream>

const char* url = "https://github.com/Dashro/Playground.git";
const char* path = "./repo";
git_repository* repo = nullptr;

int credentials_cb(git_cred** out, const char* url, const char* username_from_url,
    unsigned int allowed_types, void* payload)
{
    int error;
    const char* user = "Dashro";
    const char* pass = "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";

    printf("Provide credentials");

    return git_cred_userpass_plaintext_new(out, user, pass);
}

void checkError(int error) {
    if (error < 0) {
        const git_error* e = git_error_last();
        printf("Error %d/%d: %s\n", error, e->klass, e->message);
        exit(error);
    }
}

void clone() {
    checkError(git_clone(&repo, url, path, nullptr));
}

void open() {
    checkError(git_repository_open(&repo, path));
}

void add() {
    git_index* index = nullptr;
    git_strarray pathspec{};
    auto match_cb = [](const char* path, const char* spec, void* payload) {
        return 0;
        };

    checkError(git_repository_index(&index, repo));

    checkError(git_index_update_all(index, &pathspec, match_cb, nullptr));

    git_index_write(index);
    git_index_free(index);
}

void commit() {
    git_oid commit_oid, tree_oid;
    git_tree* tree;
    git_index* index;
    git_object* parent = NULL;
    git_reference* ref = NULL;
    git_signature* signature;
    const char* comment = "Test commit";

    auto error = git_revparse_ext(&parent, &ref, repo, "HEAD");

    if (error == GIT_ENOTFOUND) {
        printf("HEAD not found. Creating first commit\n");
        error = 0;
    }
    else if (error != 0) {
        const git_error* err = git_error_last();
        if (err) printf("ERROR %d: %s\n", err->klass, err->message);
        else printf("ERROR %d: no detailed info\n", error);
    }

    checkError(git_repository_index(&index, repo));
    checkError(git_index_write_tree(&tree_oid, index));
    checkError(git_index_write(index));

    checkError(git_tree_lookup(&tree, repo, &tree_oid));

    checkError(git_signature_default(&signature, repo));

    checkError(git_commit_create_v(
        &commit_oid,
        repo,
        "HEAD",
        signature,
        signature,
        NULL,
        comment,
        tree,
        parent ? 1 : 0, parent));

    git_index_free(index);
    git_signature_free(signature);
    git_tree_free(tree);
    git_object_free(parent);
    git_reference_free(ref);
}

void push() {
    git_push_options options;
    git_remote* remote = NULL;
    char* refspec = "refs/heads/master";
    const git_strarray refspecs = {
      &refspec,
      1
    };

    checkError(git_remote_lookup(&remote, repo, "origin"));
    checkError(git_push_options_init(&options, GIT_PUSH_OPTIONS_VERSION));

    options.callbacks.credentials = credentials_cb;

    checkError(git_remote_push(remote, &refspecs, &options));
}

void add_commit_push() {
    add();
    commit();
    push();
}

void fetch() {
    git_remote* remote;
    git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;

    fetch_opts.callbacks.credentials = credentials_cb;

    checkError(git_remote_lookup(&remote, repo, "origin"));
    checkError(git_remote_fetch(remote, nullptr, &fetch_opts, "fetch"));

    git_remote_free(remote);
}

int perform_fastforward(git_repository* repo, const git_oid* target_oid, int is_unborn) {
    git_checkout_options ff_checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
    git_reference* target_ref = nullptr;
    git_reference* new_target_ref = nullptr;
    git_object* target = nullptr;

    /* HEAD exists, just lookup and resolve */
    checkError(git_repository_head(&target_ref, repo));

    /* Lookup the target object */
    checkError(git_object_lookup(&target, repo, target_oid, GIT_OBJECT_COMMIT));

    /* Checkout the result so the workdir is in the expected state */
    ff_checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
    checkError(git_checkout_tree(repo, target, &ff_checkout_options));

    /* Move the target reference to the target OID */
    checkError(git_reference_set_target(&new_target_ref, target_ref, target_oid, NULL));

    git_reference_free(target_ref);
    git_reference_free(new_target_ref);
    git_object_free(target);

    return 0;
}

void create_merge_commit(git_repository* repo, git_index* index, const git_oid* target_oid) {
    git_oid tree_oid, commit_oid;
    git_tree* tree = nullptr;
    git_signature* sign = nullptr;
    git_reference* merge_ref = nullptr;
    git_annotated_commit* merge_commit;
    git_reference* head_ref = nullptr;
    git_commit** parents = (git_commit**)calloc(2, sizeof(git_commit*));
    const char* msg_target = nullptr;
    size_t msglen = 0;
    char* msg;

    /* Grab our needed references */
    checkError(git_repository_head(&head_ref, repo));

    /* Maybe that's a ref, so DWIM it */
    checkError(git_reference_dwim(&merge_ref, repo, "master"));
    git_annotated_commit_from_ref(&merge_commit, repo, merge_ref);

    /* Grab a signature */
    checkError(git_signature_default(&sign, repo));

#define MERGE_COMMIT_MSG "Merge %s '%s'"
    /* Prepare a standard merge commit message */
    if (merge_ref != NULL) {
        checkError(git_branch_name(&msg_target, merge_ref));
    }
    else {
        msg_target = git_oid_tostr_s(git_annotated_commit_id(merge_commit));
    }

    msglen = snprintf(NULL, 0, MERGE_COMMIT_MSG, (merge_ref ? "branch" : "commit"), msg_target);
    if (msglen > 0) msglen++;
    msg = (char*)malloc(msglen);
    snprintf(msg, msglen, MERGE_COMMIT_MSG, (merge_ref ? "branch" : "commit"), msg_target);

    /* Setup our parent commits */
    checkError(git_reference_peel((git_object**)&parents[0], head_ref, GIT_OBJECT_COMMIT));
    checkError(git_commit_lookup(&parents[1], repo, target_oid));

    /* Prepare our commit tree */
    checkError(git_index_write_tree(&tree_oid, index));
    checkError(git_tree_lookup(&tree, repo, &tree_oid));

    /* Commit time ! */
    checkError(git_commit_create(&commit_oid,
        repo, git_reference_name(head_ref),
        sign, sign,
        NULL, msg,
        tree,
        1 + 1, (const git_commit**)parents));

    /* We're done merging, cleanup the repository state */
    git_repository_state_cleanup(repo);

    git_tree_free(tree);
    git_signature_free(sign);
    git_reference_free(merge_ref);
    git_annotated_commit_free(merge_commit);
    git_reference_free(head_ref);
    git_commit_free(parents[0]);
    git_commit_free(parents[1]);
    free(parents);
    free(msg);
}

void merge() {
    auto state = git_repository_state(repo);
    if (state != GIT_REPOSITORY_STATE_NONE) {
        fprintf(stderr, "repository is in unexpected state %d\n", state);
    }

    git_oid branchOidToMerge;
    auto fetchhead_ref_cb = [](const char* ref_name, const char* remote_url, const git_oid* oid, unsigned int is_merge, void* payload) {
        if (is_merge) {
            memcpy(payload, oid, sizeof(git_oid));
        }
        return 0;
        };

    git_repository_fetchhead_foreach(repo, fetchhead_ref_cb, &branchOidToMerge);
    git_annotated_commit* their_heads[1]{};

    checkError(git_annotated_commit_lookup(&their_heads[0], repo, &branchOidToMerge));

    git_merge_analysis_t anout{};
    git_merge_preference_t pout{};

    checkError(git_merge_analysis(&anout, &pout, repo, (const git_annotated_commit**)their_heads, 1));

    if (anout & GIT_MERGE_ANALYSIS_UP_TO_DATE) {
        std::cout << "up to date";
    }
    else if (anout & GIT_MERGE_ANALYSIS_FASTFORWARD) {
        std::cout << "fast-forwarding";
        perform_fastforward(repo, &branchOidToMerge, 0);
    }
    else if (anout & GIT_MERGE_ANALYSIS_NORMAL) {
        std::cout << "normal merge";

        git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;

        checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_ALLOW_CONFLICTS;

        checkError(git_merge(repo,
            (const git_annotated_commit**)their_heads, 1,
            &merge_opts, &checkout_opts));

        git_index* index;
        checkError(git_repository_index(&index, repo));

        if (git_index_has_conflicts(index)) {
            /* Handle conflicts */
            std::cout << "We have conflicts!\n";
        }
        else {
            create_merge_commit(repo, index, &branchOidToMerge);
            printf("Merge made\n");
        }
    }

    git_annotated_commit_free(their_heads[0]);
    git_repository_state_cleanup(repo);
}

void pull() {
    fetch();
    merge();
}

int main() {
    std::cout << "Starting";

    git_libgit2_init();

    open();
    add();
    commit();

    pull();

    push();

    git_libgit2_shutdown();
}