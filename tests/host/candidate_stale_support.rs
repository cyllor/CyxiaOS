    pub fn stale_scope_scenario(){
        use crate::learning_evidence::execution_trace::ControlDenial;
        let make=||ControlDenial{action:Action::CpuWeight(2),apply:ID,stamp:STAMP,observed_ns:100_001_000,
            expected_core:1,current_core:2,expected_ledger:1,current_ledger:1,flags:1,error:Error::Stale};
        for wrong in 0..13 {
            reset();with(|_|commit(Some(STAMP),ID)).unwrap();let mut e=make();
            with(|_|{match wrong {
                0=>e.apply.boot_epoch+=1,1=>e.apply.controller_epoch+=1,2=>e.apply.action_index+=1,
                3=>e.apply.target=key(13),4=>e.apply.target.generation+=1,5=>e.stamp.version=0,
                6=>e.stamp.snapshot_ns-=1,7=>e.action=Action::SpawnTokens(1),8=>e.flags=8,
                9=>e.error=Error::Auth,10=>root_mut().phase=Phase::Complete,
                11=>root_mut().request.as_mut().unwrap().kind=TrialKind::Baseline,
                12=>root_mut().token.as_mut().unwrap().owner=key(8),_=>unreachable!()};
                candidate_stale(&e);Ok(())}).unwrap();
            assert_eq!(crate::domain_evidence::candidate_stale_header()[2],0,"foreign candidate denial acquired current scope: {wrong}");
        }
        reset();with(|_|{commit(Some(STAMP),ID)?;candidate_stale(&make());Ok(())}).unwrap();
        let first=crate::domain_evidence::candidate_stale_header();assert_eq!(first[2],1);assert_eq!(first[3],1);
        let mut e=make();e.current_ledger=99;e.flags=2;e.observed_ns+=1;
        with(|_|{candidate_stale(&e);Ok(())}).unwrap();let next=crate::domain_evidence::candidate_stale_header();
        assert_eq!(next[2],2);assert_eq!(&next[4..35],&first[4..35],"first candidate stale facts were overwritten");
        assert_eq!(next[35]%2,0);assert!(next[35]>first[35]);
        println!("candidate stale scope and first retention passed");
    }
